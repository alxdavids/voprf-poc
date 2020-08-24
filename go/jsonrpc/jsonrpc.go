package jsonrpc

import "github.com/alxdavids/voprf-poc/go/oerr"

// Request describes the structure of a JSONRPC request
type Request struct {
	Version string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  RequestParams `json:"params"`
	ID      int           `json:"id"`
}

// RequestParams objects are sent as the main payload of the Request object
type RequestParams struct {
	Data        []string `json:"data"`
	Ciphersuite int      `json:"ciph"`
}

// ResponseSuccess constructs a successful JSONRPC response back to a
// client
type ResponseSuccess struct {
	Version string         `json:"jsonrpc"`
	Result  ResponseResult `json:"result"`
	ID      int            `json:"id"`
}

// ResponseResult objects contain the main payload of Response object
type ResponseResult struct {
	Data  []string `json:"data"`
	Proof []string `json:"proof"`
}

// ResponseError constructs a failed JSONRPC response back to a client
type ResponseError struct {
	Version string         `json:"jsonrpc"`
	Error   oerr.ErrorJSON `json:"error"`
	ID      int            `json:"id"`
}
