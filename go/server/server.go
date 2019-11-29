package server

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/alxdavids/oprf-poc/go/oerr"
	"github.com/alxdavids/oprf-poc/go/oprf"
	gg "github.com/alxdavids/oprf-poc/go/oprf/groups"
)

// JSONRPCRequest describes the structure of a JSONRPC request
type JSONRPCRequest struct {
	Version string   `json:"jsonrpc"`
	Method  string   `json:"method"`
	Params  []string `json:"params"`
	ID      int      `json:"id"`
}

// JSONRPCResponseSuccess constructs a successful JSONRPC response back to a
// client
type JSONRPCResponseSuccess struct {
	Version string   `json:"jsonrpc"`
	Result  []string `json:"result"`
	ID      int      `json:"id"`
}

// JSONRPCResponseError constructs a failed JSONRPC response back to a client
type JSONRPCResponseError struct {
	Version string         `json:"jsonrpc"`
	Error   oerr.ErrorJSON `json:"error"`
	ID      int            `json:"id"`
}

// Config corresponds to the actual HTTP instantiation of the server in the OPRF
// protocol, it contains an oprf.Server object for processing OPRF operations
type Config struct {
	osrv oprf.Server
	hsrv http.Server
	tls  bool
}

// CreateConfig returns a HTTP Server object
func CreateConfig(tls bool, ciphersuite string, pogInit gg.PrimeOrderGroup) (*Config, oerr.Error) {
	ptpnt, err := oprf.Server{}.Setup(ciphersuite, pogInit)
	if err.Err() != nil {
		return nil, err
	}
	osrv, err := oprf.CastServer(ptpnt)
	if err.Err() != nil {
		return nil, err
	}

	// create server config
	cfg := &Config{
		osrv: osrv,
		hsrv: http.Server{
			Addr:           ":3001",
			ReadTimeout:    10 * time.Second,
			WriteTimeout:   10 * time.Second,
			MaxHeaderBytes: 1 << 20,
		},
		tls: tls,
	}
	cfg.hsrv.Handler = http.HandlerFunc(cfg.handleOPRF)
	return cfg, oerr.Nil()
}

// ListenAndServe listens for connections and responds to request using the OPRF
// functionality
func (cfg *Config) ListenAndServe() oerr.Error {
	fmt.Println("Server listening on port 3001")
	for true {
		e := cfg.hsrv.ListenAndServe()
		if e != nil {
			return oerr.ErrServerInternal
		}
	}
	return oerr.Nil()
}

// handleOPRF handles the HTTP request that arrives
func (cfg *Config) handleOPRF(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	jsonReq, e := readRequestBody(r)
	if e != nil {
		respError(w, oerr.ErrJSONRPCParse, http.StatusBadRequest)
		return
	}

	// parse and action JSONRPC request
	ret, err, status := cfg.processJSONRPCRequest(jsonReq)
	if err.Err() != nil {
		respError(w, err, status)
		return
	}

	// return success response
	respSuccess(w, []string{hex.EncodeToString(ret)})
}

// processJSONRPCRequest parses the JSONRPC request and attempts to run the OPRF
// functionality specified in the request
func (cfg *Config) processJSONRPCRequest(jsonReq *JSONRPCRequest) ([]byte, oerr.Error, int) {
	var ret []byte
	var err oerr.Error
	params := jsonReq.Params
	switch jsonReq.Method {
	case "eval":
		if len(params) == 0 {
			return nil, oerr.ErrJSONRPCInvalidMethodParams, http.StatusBadRequest
		}
		// evaluate OPRF
		ret, err = cfg.processEval(params[0])
		break
	default:
		return nil, oerr.ErrJSONRPCMethodNotFound, http.StatusBadRequest
	}
	if err.Err() != nil {
		return nil, err, http.StatusBadRequest
	}

	return ret, oerr.Nil(), -1
}

// processEval processes an evaluation request from the client
func (cfg *Config) processEval(param string) ([]byte, oerr.Error) {
	buf, e := hex.DecodeString(param)
	if e != nil {
		return nil, oerr.ErrJSONRPCInvalidMethodParams
	}

	// create GroupElement
	osrv := cfg.osrv
	pog := osrv.Ciphersuite().POG()
	ge := gg.CreateGroupElement(pog)
	var err oerr.Error
	ge, err = ge.Deserialize(buf)
	if err.Err() != nil {
		return nil, err
	}

	// compute OPRF evaluation
	geEval, err := cfg.osrv.Eval(osrv.SecretKey(), ge)
	if err.Err() != nil {
		return nil, err
	}

	// serialize output point and return
	return geEval.Serialize()
}

// readRequestBody tries to read a JSONRPCRequest object from the HTTP Request
func readRequestBody(r *http.Request) (*JSONRPCRequest, error) {
	req := &JSONRPCRequest{}
	e := json.NewDecoder(r.Body).Decode(req)
	if e != nil {
		return nil, e
	}
	return req, nil
}

// respSuccess constructs a JSONRPC success response to send back to the client
func respSuccess(w http.ResponseWriter, result []string) {
	resp, _ := json.Marshal(JSONRPCResponseSuccess{Version: "2.0", Result: result, ID: 1})
	w.Write(resp)
}

// constructs a JSONRPC parse error to return
func respError(w http.ResponseWriter, e oerr.Error, status int) {
	// if an error occurs here then we have no hope so I'm going to
	// ignore it
	resp, _ := json.Marshal(JSONRPCResponseError{Version: "2.0", Error: e.JSON(), ID: 1})
	w.WriteHeader(status)
	w.Write(resp)
	fmt.Printf("Error occurred processing client request (%v)\n", e.Err())
}
