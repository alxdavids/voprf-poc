package client

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"

	"github.com/alxdavids/oprf-poc/go/jsonrpc"
	"github.com/alxdavids/oprf-poc/go/oprf"
	gg "github.com/alxdavids/oprf-poc/go/oprf/groups"
)

var (
	storedInputs       [][]byte
	storedBlinds       []*big.Int
	storedFinalOutputs [][]byte
)

// Config holds all the relevant information for a client-side OPRF
// implementation
type Config struct {
	ocli       oprf.Client
	n          int
	addr       string
	outputPath string
}

// CreateConfig instantiates the client that will communicate with the HTTP
// server that runs the OPRF server-side instance
func CreateConfig(ciphersuite string, pogInit gg.PrimeOrderGroup, n int, outputPath string) (*Config, error) {
	ptpnt, err := oprf.Client{}.Setup(ciphersuite, pogInit)
	if err != nil {
		return nil, err
	}
	ocli, err := oprf.CastClient(ptpnt)
	if err != nil {
		return nil, err
	}

	// create server config
	cfg := &Config{
		ocli:       ocli,
		n:          n,
		addr:       "http://localhost:3001",
		outputPath: outputPath,
	}
	return cfg, nil
}

// SendOPRFRequest constructs and sends an OPRF request to the OPRF server
// instance. The response is processed by running hte Unblind() and Finalize()
// functionalities.
func (cfg *Config) SendOPRFRequest() error {
	oprfReq, err := cfg.createOPRFRequest()
	if err != nil {
		return err
	}
	buf, err := json.Marshal(oprfReq)
	if err != nil {
		return err
	}

	// make HTTP request and parse Response
	resp, err := http.Post(cfg.addr, "application/json", bytes.NewBuffer(buf))
	if err != nil {
		return err
	}

	// read response body
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// attempt to parse Server JSONRPC response
	jsonrpcResp, err := cfg.parseJSONRPCResponse(body)
	if err != nil {
		return err
	}

	// Process and finalize the server response, and then store
	storedFinalOutputs, err = cfg.processServerResponse(jsonrpcResp)
	if err != nil {
		return err
	}
	return nil
}

// createOPRFRequest creates the first message in the OPRF protocol to send to
// the OPRF server. The parameter n indicates the number of tokens that should
// be sent
//
// TODO: allow n to be greater than 1
func (cfg *Config) createOPRFRequest() (*jsonrpc.Request, error) {
	n := cfg.n
	if n < 1 {
		return nil, errors.New("The value of n must be greater than 0")
	}
	var inputs [][]byte
	var blinds []*big.Int
	var encodedElements [][]byte
	for i := 0; i < n; i++ {
		// sample a random input
		buf := make([]byte, 32)
		_, err := rand.Read(buf)
		if err != nil {
			return nil, err
		}
		inputs = append(inputs, buf)

		// create a blinded group element
		ge, blind, err := cfg.ocli.Blind(buf)
		if err != nil {
			return nil, err
		}
		blinds = append(blinds, blind)

		// Encode group element
		encoded, err := ge.Serialize()
		if err != nil {
			return nil, err
		}
		encodedElements = append(encodedElements, encoded)
	}
	// store in globals
	storedInputs = inputs
	storedBlinds = blinds
	// return JSONRPC Request object
	return cfg.createJSONRPCRequest(encodedElements, 1), nil
}

func (cfg *Config) processServerResponse(jsonrpcResp *jsonrpc.ResponseSuccess) ([][]byte, error) {
	// parse returned group element and unblind
	params := jsonrpcResp.Result.Data
	pog := cfg.ocli.Ciphersuite().POG()
	var finalOutputs [][]byte
	for i := 0; i < cfg.n; i++ {
		buf, err := hex.DecodeString(params[i])
		if err != nil {
			return nil, err
		}
		Z, err := gg.CreateGroupElement(pog).Deserialize(buf)
		if err != nil {
			return nil, err
		}
		N, err := cfg.ocli.Unblind(Z, storedBlinds[i])
		if err != nil {
			return nil, err
		}
		aux := []byte("oprf_finalization_step")
		y, err := cfg.ocli.Finalize(N, storedInputs[i], aux)
		if err != nil {
			return nil, err
		}
		finalOutputs = append(finalOutputs, y)
	}
	return finalOutputs, nil
}

// createJSONRPCRequest creates the JSONRPC Request object for sending to the
// OPRF server instance
func (cfg *Config) createJSONRPCRequest(eles [][]byte, id int) *jsonrpc.Request {
	var hexParams []string
	for _, buf := range eles {
		hexParams = append(hexParams, hex.EncodeToString(buf))
	}
	return &jsonrpc.Request{
		Version: "2.0",
		Method:  "eval",
		Params: jsonrpc.RequestParams{
			Data: hexParams,
		},
		ID: id,
	}
}

// parseJSONRPCResponse attempts to parse a JSONRPC successful response object.
// If the server has sent an error response then it returns an error instead.
func (cfg *Config) parseJSONRPCResponse(body []byte) (*jsonrpc.ResponseSuccess, error) {
	// attempt to parse success
	jsonrpcSuccess := &jsonrpc.ResponseSuccess{}
	jsonrpcError := &jsonrpc.ResponseError{}
	e := json.Unmarshal(body, jsonrpcSuccess)
	if e != nil {
		return nil, e
	}

	// if this occurs then it's likely that an error occurred
	if len(jsonrpcSuccess.Result.Data) == 0 {
		// try and decode error response
		e2 := json.Unmarshal(body, jsonrpcError)
		if e2 != nil || jsonrpcError.Error.Message == "" {
			// either error or unable to parse error
			return nil, errors.New("Failed to parse JSONRPC error response")
		}
		return nil, errors.New(jsonrpcError.Error.Message)
	}

	// otherwise return success
	return jsonrpcSuccess, nil
}

// SetPublicKey sets a hex-encoded public key for the underlying OPRF client for
// use when verifying VOPRF evaluations from the server
func (cfg *Config) SetPublicKey(pk string) error {
	buf, err := hex.DecodeString(pk)
	if err != nil {
		return err
	}
	Y, err := gg.CreateGroupElement(cfg.ocli.Ciphersuite().POG()).Deserialize(buf)
	if err != nil {
		return err
	}
	cfg.ocli.SetPublicKey(Y)
	return nil
}

// PrintStorage outputs all the current stored variables to either stdout or file
// (if a filepath is specified)
func (cfg *Config) PrintStorage() error {
	var bufBlinds [][]byte
	for _, v := range storedBlinds {
		bufBlinds = append(bufBlinds, v.Bytes())
	}

	// construct output strings
	arrays := [][][]byte{storedInputs, bufBlinds, storedFinalOutputs}
	outputStrings := make([]string, 3)
	for j, s := range arrays {
		outString := ""
		for i, byt := range s {
			outString = outString + hex.EncodeToString(byt)
			if i != len(storedInputs)-1 {
				outString = outString + "\n"
			}
		}
		outputStrings[j] = outString
	}

	// output to file if one is defined, otherwise to stdout
	if cfg.outputPath != "" {
		fileNames := []string{"/stored_inputs.txt", "/stored_blinds.txt", "/stored_final_outputs.txt"}
		for i, f := range fileNames {
			e := ioutil.WriteFile(cfg.outputPath+f, []byte(outputStrings[i]), 0755)
			if e != nil {
				return e
			}
		}
	} else {
		headers := []string{"Inputs", "Blinds", "Outputs"}
		for i, h := range headers {
			fmt.Println("***********")
			fmt.Println(h)
			fmt.Println("===========")
			fmt.Println(outputStrings[i])
			fmt.Println("***********")
		}
	}
	return nil
}
