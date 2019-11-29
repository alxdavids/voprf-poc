package server

import (
	"encoding/hex"
	"encoding/json"
	"net/http"

	"github.com/alxdavids/oprf-poc/go/oerr"
	"github.com/alxdavids/oprf-poc/go/oprf"
	gg "github.com/alxdavids/oprf-poc/go/oprf/groups"
)

// JSONRPCRequest describes the structure of a JSONRPC request
type JSONRPCRequest struct {
	Version string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  interface{}
	ID      int `json:"id"`
}

// JSONRPCResponseSuccess constructs a successful JSONRPC response back to a
// client
type JSONRPCResponseSuccess struct {
	Version string `json:"jsonrpc"`
	Result  string `json:"result"`
	ID      int    `json:"id"`
}

// JSONRPCResponseError constructs a failed JSONRPC response back to a client
type JSONRPCResponseError struct {
	Version string     `json:"jsonrpc"`
	Error   oerr.Error `json:"error"`
	ID      int        `json:"id"`
}

// Config corresponds to the actual HTTP instantiation of the server in the OPRF
// protocol, it contains an oprf.Server object for processing OPRF operations
type Config struct {
	osrv oprf.Server
	hsrv http.Server
}

// CreateConfig returns a HTTP Server object
func CreateConfig(tls bool, ciphersuite string, pogInit gg.PrimeOrderGroup) (Config, oerr.Error) {
	ptpnt, err := oprf.Server{}.Setup(ciphersuite, pogInit)
	if err.Err() != nil {
		return Config{}, err
	}
	osrv, err := oprf.CastServer(ptpnt)
	if err.Err() != nil {
		return Config{}, err
	}

	return Config{osrv: osrv}, oerr.Nil()
}

// handleOPRF handles the HTTP request that arrives
func (cfg *Config) handleOPRF(w http.ResponseWriter, r *http.Request) {
	jsonReq, e := readRequestBody(r)
	if e != nil {
		w.Write(respError(oerr.ErrJSONRPCParse))
	}

	switch jsonReq.Method {
	case "eval":
		cfg.processEval((jsonReq.Params.([]string))[0])
		break
	default:
		w.Write(respError(oerr.ErrJSONRPCMethodNotFound))
	}
}

// processEval processes an evaluation request from the client
func (cfg *Config) processEval(param string) ([]byte, oerr.Error) {
	buf, e := hex.DecodeString(param)
	if e != nil {
		return nil, oerr.ErrJSONRPCInvalidMethodParams
	}

	// create GroupElement
	pog := cfg.osrv.Ciphersuite().POG()
	var ge gg.GroupElement
	ge = ge.New(pog)
	var err oerr.Error
	ge, err = ge.Deserialize(buf)
	if err.Err() != nil {
		return nil, err
	}
	return nil, oerr.Nil()
}

// readRequestBody tries to read a JSONRPCRequest object from the HTTP Request
func readRequestBody(r *http.Request) (*JSONRPCRequest, error) {
	body, e := r.GetBody()
	if e != nil {
		return nil, e
	}
	var buf []byte
	_, e = body.Read(buf)
	if e != nil {
		return nil, e
	}
	req := &JSONRPCRequest{}
	e = json.Unmarshal(buf, req)
	if e != nil {
		return nil, e
	}
	return req, nil
}

// constructs a JSONRPC parse error to return
func respError(e oerr.Error) []byte {
	// if an error occurs here then we have no hope so I'm going to
	// ignore it
	resp, _ := json.Marshal(JSONRPCResponseError{Version: "2.0", Error: e, ID: 1})
	return resp
}
