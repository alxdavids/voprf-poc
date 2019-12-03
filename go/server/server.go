package server

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/alxdavids/oprf-poc/go/jsonrpc"
	"github.com/alxdavids/oprf-poc/go/oerr"
	"github.com/alxdavids/oprf-poc/go/oprf"
	gg "github.com/alxdavids/oprf-poc/go/oprf/groups"
)

// Config corresponds to the actual HTTP instantiation of the server in the OPRF
// protocol, it contains an oprf.Server object for processing OPRF operations
type Config struct {
	osrv oprf.Server // Server object for performing OPRF operations
	hsrv http.Server // HTTP Server
	max  int         // Max number of OPRF evaluations to be permitted in one go
	tls  bool        // TODO: whether TLS is supported by the server
}

// CreateConfig returns a HTTP Server object
func CreateConfig(ciphersuite string, pogInit gg.PrimeOrderGroup, max int, tls bool) (*Config, error) {
	ptpnt, err := oprf.Server{}.Setup(ciphersuite, pogInit)
	if err != nil {
		return nil, err
	}
	osrv, err := oprf.CastServer(ptpnt)
	if err != nil {
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
		max: max,
		tls: tls,
	}
	cfg.hsrv.Handler = http.HandlerFunc(cfg.handleOPRF)
	return cfg, nil
}

// ListenAndServe listens for connections and responds to request using the OPRF
// functionality
func (cfg *Config) ListenAndServe() error {
	fmt.Println("Server listening on port 3001")
	for true {
		e := cfg.hsrv.ListenAndServe()
		if e != nil {
			return oerr.ErrServerInternal
		}
	}
	return nil
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
	ret, err := cfg.processJSONRPCRequest(jsonReq)
	if err != nil {
		respError(w, err, http.StatusBadRequest)
		return
	}

	// return success response
	respSuccess(w, ret, jsonReq.ID)
}

// processJSONRPCRequest parses the JSONRPC request and attempts to run the OPRF
// functionality specified in the request
func (cfg *Config) processJSONRPCRequest(jsonReq *jsonrpc.Request) ([][]byte, error) {
	var ret [][]byte
	var err error
	if jsonReq.Version != "2.0" {
		return nil, oerr.ErrJSONRPCInvalidRequest
	}

	params := jsonReq.Params
	fmt.Println(jsonReq)
	switch jsonReq.Method {
	case "eval":
		if len(params) < 1 {
			return nil, oerr.ErrJSONRPCInvalidMethodParams
		}
		// evaluate OPRF
		ret, err = cfg.processEval(params)
		break
	default:
		return nil, oerr.ErrJSONRPCMethodNotFound
	}
	if err != nil {
		return nil, err
	}

	return ret, nil
}

// processEval processes an evaluation request from the client over the blinded
// group elements that they provide
func (cfg *Config) processEval(params []string) ([][]byte, error) {
	lenParams := len(params)
	if lenParams > cfg.max {
		return nil, oerr.ErrJSONRPCInvalidMethodParams
	}
	evalsOut := make([][]byte, len(params))
	for i, s := range params {
		buf, e := hex.DecodeString(s)
		if e != nil {
			return nil, oerr.ErrJSONRPCInvalidMethodParams
		}

		// create GroupElement
		osrv := cfg.osrv
		pog := osrv.Ciphersuite().POG()
		ge, err := gg.CreateGroupElement(pog).Deserialize(buf)
		if err != nil {
			return nil, err
		}

		// compute OPRF evaluation
		geEval, err := cfg.osrv.Eval(osrv.SecretKey(), ge)
		if err != nil {
			return nil, err
		}

		// serialize output
		out, err := geEval.Serialize()
		if err != nil {
			return nil, err
		}
		evalsOut[i] = out
	}

	// serialize output point and return
	return evalsOut, nil
}

// readRequestBody tries to read a JSONRPCRequest object from the HTTP Request
func readRequestBody(r *http.Request) (*jsonrpc.Request, error) {
	defer r.Body.Close()
	req := &jsonrpc.Request{}
	e := json.NewDecoder(r.Body).Decode(req)
	if e != nil {
		return nil, e
	}
	return req, nil
}

// respSuccess constructs a JSONRPC success response to send back to the client
func respSuccess(w http.ResponseWriter, result [][]byte, id int) {
	resultStrings := make([]string, len(result))
	for i, s := range result {
		resultStrings[i] = hex.EncodeToString(s)
	}
	resp, _ := json.Marshal(jsonrpc.ResponseSuccess{Version: "2.0", Result: resultStrings, ID: id})
	w.Write(resp)
}

// constructs a JSONRPC parse error to return
func respError(w http.ResponseWriter, e error, status int) {
	// Parse error type for returning JSONRPC error response
	jsonrpcError := oerr.GetJSONRPCError(e)

	// if an error occurs here then we have no hope so I'm going to
	// ignore it
	resp, _ := json.Marshal(jsonrpc.ResponseError{Version: "2.0", Error: jsonrpcError, ID: 1})
	w.WriteHeader(status)
	w.Write(resp)
	fmt.Printf("Error occurred processing client request (message: %v)\n", e)
}
