package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"sync"

	"github.com/coreos/go-tspi/attestation"
	"github.com/coreos/go-tspi/tspi"
)

var wellKnown [20]byte

var pcrmutex sync.RWMutex

func setupContext() (*tspi.Context, *tspi.TPM, error) {
	context, err := tspi.NewContext()
	if err != nil {
		return nil, nil, err
	}

	context.Connect()
	tpm := context.GetTPM()
	tpmpolicy, err := context.CreatePolicy(tspi.TSS_POLICY_USAGE)
	if err != nil {
		return nil, nil, err
	}
	tpm.AssignPolicy(tpmpolicy)
	tpmpolicy.SetSecret(tspi.TSS_SECRET_MODE_SHA1, wellKnown[:])

	return context, tpm, nil
}

func cleanupContext(context *tspi.Context) {
	context.Close()
}

type ekcertResponse struct {
	EKCert []byte
}

func getEkcert(rw http.ResponseWriter, request *http.Request) {
	var output ekcertResponse

	context, _, err := setupContext()
	defer cleanupContext(context)

	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte(err.Error()))
		return
	}

	if request.Method != "GET" {
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	ekcert, err := attestation.GetEKCert(context)
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		rw.Write([]byte(err.Error()))
		return
	}

	output.EKCert = ekcert
	jsonresponse, err := json.Marshal(output)
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		rw.Write([]byte(err.Error()))
		return
	}
	rw.Write(jsonresponse)
}

type aikResponse struct {
	AIKBlob []byte
	AIKPub  []byte
}

func generateAik(rw http.ResponseWriter, request *http.Request) {
	var output aikResponse

	context, _, err := setupContext()
	defer cleanupContext(context)

	if request.Method != "POST" {
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	aikpub, aikblob, err := attestation.CreateAIK(context)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte(err.Error()))
		return
	}

	output.AIKPub = aikpub
	output.AIKBlob = aikblob

	jsonresponse, err := json.Marshal(output)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte(err.Error()))
		return
	}
	rw.Write(jsonresponse)
}

type challengeData struct {
	AIK     []byte
	Asymenc []byte
	Symenc  []byte
}

type challengeResponse struct {
	Response []byte
}

func aikChallenge(rw http.ResponseWriter, request *http.Request) {
	body, err := ioutil.ReadAll(request.Body)
	var input challengeData
	var output challengeResponse

	context, _, err := setupContext()
	defer cleanupContext(context)

	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte(err.Error()))
		return
	}

	if request.Method != "POST" {
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	err = json.Unmarshal(body, &input)
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		rw.Write([]byte(err.Error()))
		return
	}

	response, err := attestation.AIKChallengeResponse(context, input.AIK, input.Asymenc, input.Symenc)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte(err.Error()))
		return
	}

	output.Response = response
	jsonresponse, err := json.Marshal(output)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte(err.Error()))
		return
	}
	rw.Write(jsonresponse)
}

type quoteData struct {
	AIK   []byte
	PCRs  []int
	Nonce []byte
}

type quoteResponse struct {
	Data       []byte
	Validation []byte
	PCRValues  [][]byte
	Events     []tspi.Log
}

func quote(rw http.ResponseWriter, request *http.Request) {
	body, err := ioutil.ReadAll(request.Body)
	var input quoteData
	var output quoteResponse

	context, tpm, err := setupContext()
	defer cleanupContext(context)

	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte(err.Error()))
		return
	}

	if request.Method != "POST" {
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	err = json.Unmarshal(body, &input)
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		rw.Write([]byte(err.Error()))
		return
	}

	pcrs, err := context.CreatePCRs(tspi.TSS_PCRS_STRUCT_INFO)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte(err.Error()))
		return
	}

	err = pcrs.SetPCRs(input.PCRs)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte(err.Error()))
		return
	}

	srk, err := context.LoadKeyByUUID(tspi.TSS_PS_TYPE_SYSTEM, tspi.TSS_UUID_SRK)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte(err.Error()))
		return
	}
	srkpolicy, err := srk.GetPolicy(tspi.TSS_POLICY_USAGE)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte(err.Error()))
		return
	}
	srkpolicy.SetSecret(tspi.TSS_SECRET_MODE_SHA1, wellKnown[:])

	aik, err := context.LoadKeyByBlob(srk, input.AIK)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte(err.Error()))
		return
	}

	pcrmutex.Lock()
	data, validation, err := tpm.GetQuote(aik, pcrs, input.Nonce)
	if err != nil {
		pcrmutex.Unlock()
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte(err.Error()))
		return
	}

	pcrvalues, err := pcrs.GetPCRValues()
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte(err.Error()))
		pcrmutex.Unlock()
		return
	}

	log, err := tpm.GetEventLog()
	pcrmutex.Unlock()
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte(err.Error()))
		return
	}
	output.Data = data
	output.Validation = validation
	output.PCRValues = pcrvalues
	output.Events = log

	jsonoutput, err := json.Marshal(output)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte(err.Error()))
		return
	}

	rw.Write(jsonoutput)
}

type extendData struct {
	Pcr       int
	Eventtype int
	Data      []byte
	Event     string
}

func extend(rw http.ResponseWriter, request *http.Request) {
	body, err := ioutil.ReadAll(request.Body)
	var data extendData

	context, tpm, err := setupContext()
	defer cleanupContext(context)

	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte(err.Error()))
		return
	}

	if request.Method != "POST" {
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	err = json.Unmarshal(body, &data)

	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		rw.Write([]byte(err.Error()))
		return
	}

	pcrmutex.Lock()
	err = tpm.ExtendPCR(data.Pcr, data.Data, data.Eventtype, []byte(data.Event))
	pcrmutex.Unlock()

	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte(err.Error()))
		return
	}
	rw.Write([]byte("OK"))
}

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %s port\n", os.Args[0])
		return
	}
	socket := fmt.Sprintf(":%s", os.Args[1])
	http.HandleFunc("/v1/extend", extend)
	http.HandleFunc("/v1/quote", quote)
	http.HandleFunc("/v1/getEkcert", getEkcert)
	http.HandleFunc("/v1/generateAik", generateAik)
	http.HandleFunc("/v1/aikChallenge", aikChallenge)
	err := http.ListenAndServe(socket, nil)
	if err != nil {
		fmt.Printf("Unable to listen - %s\n", err)
	}
}
