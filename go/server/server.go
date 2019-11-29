package server

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

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
	}
	cfg.hsrv.Handler = http.HandlerFunc(cfg.handleOPRF)
	return cfg, oerr.Nil()
}

// ListenAndServe listens for connections and responds to request using the OPRF
// functionality
func (cfg *Config) ListenAndServe() error {
	for true {
		e := cfg.hsrv.ListenAndServe()
		if e != nil {
			return e
		}
	}
	return nil
}

// handleOPRF handles the HTTP request that arrives
func (cfg *Config) handleOPRF(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	jsonReq, e := readRequestBody(r)
	if e != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write(respError(oerr.ErrJSONRPCParse))
	}

	var ret []byte
	var err oerr.Error
	switch jsonReq.Method {
	case "eval":
		ret, err = cfg.processEval((jsonReq.Params.([]string))[0])
		break
	default:
		w.WriteHeader(http.StatusBadRequest)
		w.Write(respError(oerr.ErrJSONRPCMethodNotFound))
	}
	if err.Err() != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(respError(err))
	}

	// return success response
	w.WriteHeader(http.StatusOK)
	w.Write(respSuccess(hex.EncodeToString(ret)))
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
	var ge gg.GroupElement
	ge = ge.New(pog)
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

// respSuccess constructs a JSONRPC success response to send back to the client
func respSuccess(result string) []byte {
	resp, _ := json.Marshal(JSONRPCResponseSuccess{Version: "2.0", Result: result, ID: 1})
	return resp
}

// constructs a JSONRPC parse error to return
func respError(e oerr.Error) []byte {
	// if an error occurs here then we have no hope so I'm going to
	// ignore it
	resp, _ := json.Marshal(JSONRPCResponseError{Version: "2.0", Error: e, ID: 1})
	return resp
}
