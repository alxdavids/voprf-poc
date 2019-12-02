package jsonrpc

import "github.com/alxdavids/oprf-poc/go/oerr"

// Request describes the structure of a JSONRPC request
type Request struct {
	Version string   `json:"jsonrpc"`
	Method  string   `json:"method"`
	Params  []string `json:"params"`
	ID      int      `json:"id"`
}

// ResponseSuccess constructs a successful JSONRPC response back to a
// client
type ResponseSuccess struct {
	Version string   `json:"jsonrpc"`
	Result  []string `json:"result"`
	ID      int      `json:"id"`
}

// ResponseError constructs a failed JSONRPC response back to a client
type ResponseError struct {
	Version string         `json:"jsonrpc"`
	Error   oerr.ErrorJSON `json:"error"`
	ID      int            `json:"id"`
}
