package server

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/alxdavids/voprf-poc/go/jsonrpc"
	"github.com/alxdavids/voprf-poc/go/oerr"
	"github.com/alxdavids/voprf-poc/go/oprf"
	gg "github.com/alxdavids/voprf-poc/go/oprf/groups"
)

// Config corresponds to the actual HTTP instantiation of the server in the OPRF
// protocol, it contains an oprf.Server object for processing OPRF operations
type Config struct {
	osrv  oprf.Server // Server object for performing OPRF operations
	hsrv  http.Server // HTTP Server
	max   int         // Max number of OPRF evaluations to be permitted in one go
	tls   bool        // TODO: TLS is still not supported
	test  bool        // Indicates that the server runs in test mode
	tDleq string      // a fixed scalar value used for generating DLEQ proofs
}

// CreateConfig returns a HTTP Server object
func CreateConfig(ciphersuite string, pogInit gg.PrimeOrderGroup, max int, tls, test bool, tDleq string) (*Config, error) {
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
		max:   max,
		tls:   tls,
		test:  test,
		tDleq: tDleq,
	}
	cfg.hsrv.Handler = http.HandlerFunc(cfg.handleOPRF)
	return cfg, nil
}

// ListenAndServe listens for connections and responds to request using the OPRF
// functionality
func (cfg *Config) ListenAndServe(key string) error {
	fmt.Println("Server listening on port 3001")

	// if a fixed key is provided then we should use this one
	if key != "" {
		k, ok := new(big.Int).SetString(key, 16)
		if !ok {
			panic("Bad key value specified")
		}
		pog := cfg.osrv.Ciphersuite().POG()
		pubKey, err := pog.GeneratorMult(k)
		if err != nil {
			return oerr.ErrServerInternal
		}
		cfg.osrv = cfg.osrv.SetSecretKey(oprf.SecretKey{K: k, PubKey: pubKey})
	}

	// output public key (and optionally secret key values)
	sk := cfg.osrv.SecretKey()
	ser, err := sk.PubKey.Serialize()
	if err != nil {
		return err
	}
	fmt.Printf("Public key: %s\n", hex.EncodeToString(ser))
	if cfg.test {
		key := sk.K
		fmt.Printf("Secret key: %s\n", hex.EncodeToString(key.Bytes()))
	}

	// run server
	for {
		e := cfg.hsrv.ListenAndServe()
		if e != nil {
			return oerr.ErrServerInternal
		}
	}
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
func (cfg *Config) processJSONRPCRequest(jsonReq *jsonrpc.Request) (map[string][][]byte, error) {
	if jsonReq.Version != "2.0" {
		return nil, oerr.ErrJSONRPCInvalidRequest
	}

	params := jsonReq.Params
	// if the ciphersuite is empty then just attempt to evaluate
	ciph := params.Ciphersuite
	if ciph != cfg.osrv.Ciphersuite().Name() {
		return nil, oerr.ErrJSONRPCInvalidMethodParams
	}

	// check that the method is correct and if so evaluate the (V)OPRF
	var ret map[string][][]byte
	var err error
	switch jsonReq.Method {
	case "eval":
		if len(params.Data) < 1 {
			return nil, oerr.ErrJSONRPCInvalidMethodParams
		}
		// evaluate OPRF
		ret, err = cfg.processEval(params.Data)
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
func (cfg *Config) processEval(params []string) (map[string][][]byte, error) {
	lenParams := len(params)
	if lenParams > cfg.max {
		return nil, oerr.ErrJSONRPCInvalidMethodParams
	}

	l := len(params)
	inputs := make([]gg.GroupElement, l)
	osrv := cfg.osrv
	pog := osrv.Ciphersuite().POG()
	var err error
	for i, s := range params {
		buf, e := hex.DecodeString(s)
		if e != nil {
			return nil, oerr.ErrJSONRPCInvalidMethodParams
		}

		// deserialize input to GroupElement object
		ge, err := gg.CreateGroupElement(pog).Deserialize(buf)
		if err != nil {
			return nil, err
		}
		inputs[i] = ge
	}

	// compute (V)OPRF evaluation over provided inputs
	var eval oprf.Evaluation
	if cfg.tDleq == "" {
		eval, err = cfg.osrv.Eval(inputs)
	} else {
		eval, err = cfg.osrv.FixedEval(inputs, cfg.tDleq)
	}
	if err != nil {
		return nil, err
	}
	if cfg.test {
		// if testing, then we want to recompute t for helping with test vectors
		k := osrv.SecretKey().K
		c := eval.Proof.C
		s := eval.Proof.S
		t := new(big.Int).Mod(new(big.Int).Add(s, new(big.Int).Mul(c, k)), pog.Order())
		fmt.Println("DLEQ scalar t:", hex.EncodeToString(t.Bytes()))
	}

	// serialize output group elements
	evalsOut := make([][]byte, l)
	for i, Z := range eval.Elements {
		out, err := Z.Serialize()
		if err != nil {
			return nil, err
		}
		evalsOut[i] = out
	}

	// serialize proof object if the ciphersuite indicates verifiability
	serializedProof := make([][]byte, 2)
	if cfg.osrv.Ciphersuite().Verifiable() {
		serializedProof = eval.Proof.Serialize()
	}

	return map[string][][]byte{"data": evalsOut, "proof": serializedProof}, nil
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
func respSuccess(w http.ResponseWriter, result map[string][][]byte, id int) {
	data := result["data"]
	proof := result["proof"]
	// encode the provided data to hex
	evalStrings := make([]string, len(data))
	for i, s := range data {
		evalStrings[i] = hex.EncodeToString(s)
	}
	r := jsonrpc.ResponseResult{Data: evalStrings}

	// hex-encode the proof if it exists
	proofLen := len(proof)
	if proofLen > 0 {
		proofStrings := make([]string, proofLen)
		for i, s := range proof {
			proofStrings[i] = hex.EncodeToString(s)
		}
		r.Proof = proofStrings
	}

	// marshal success response
	resp, _ := json.Marshal(jsonrpc.ResponseSuccess{Version: "2.0", Result: r, ID: id})
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
