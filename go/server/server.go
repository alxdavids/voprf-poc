package server

import (
	"net/http"

	"github.com/alxdavids/oprf-poc/go/oprf"
	gg "github.com/alxdavids/oprf-poc/go/oprf/groups"
)

// JSONRPCResponseSuccess constructs a successful JSONRPC response back to a
// client
type JSONRPCResponseSuccess struct {
	Version string `json:"jsonrpc"`
	Result  string `json:"result"`
	ID      int    `json:"id"`
}

// JSONRPCResponseError constructs a failed JSONRPC response back to a client
type JSONRPCResponseError struct {
	Version string       `json:"jsonrpc"`
	Error   JSONRPCError `json:"error"`
	ID      int          `json:"id"`
}

// JSONRPCError is the Error object returned in JSPNRPCError responses
type JSONRPCError struct {
	Message string
	Code    int
}

// Server corresponds to the actual HTTP instantiation of the server in the OPRF
// protocol, it contains an oprf.Server object for processing OPRF operations
type Server struct {
	oprfServer   oprf.Server
	httpListener http.Server
}

// CreateServer returns a HTTP Server object
func CreateServer(tls bool, ciphersuite string, pogInit gg.PrimeOrderGroup) (Server, error) {
	ptpnt, err := oprf.Server{}.Setup(ciphersuite, pogInit)
	if err != nil {
		return Server{}, err
	}
	oprfSrv, err := oprf.CastServer(ptpnt)
	if err != nil {
		return Server{}, err
	}

	return Server{oprfServer: oprfSrv}, nil
}

func handleOPRF(w http.ResponseWriter, r *http.Request) {
	mux := http.NewServeMux()
	mux.HandleFunc("/eval", func(w http.ResponseWriter, r *http.Request) {
		body, err := r.GetBody()
		if err != nil {
		}
	})
}
