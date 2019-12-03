package oerr

import "errors"

var (
	// ErrJSONRPCParse indicates that a JSON-RPC parsing error occurred
	// (https://www.jsonrpc.org/specification#error_object)
	ErrJSONRPCParse = errors.New("Invalid JSON was received by the server, an error occurred on the server while parsing the JSON text")
	// ErrJSONRPCInvalidRequest indicates that the JSON-RPC request was invalid
	// (https://www.jsonrpc.org/specification#error_object)
	ErrJSONRPCInvalidRequest = errors.New("The JSON sent is not a valid Request object")
	// ErrJSONRPCMethodNotFound indicates that the specified method was not
	// found or supported (https://www.jsonrpc.org/specification#error_object)
	ErrJSONRPCMethodNotFound = errors.New("The method is not available")
	// ErrJSONRPCInvalidMethodParams indiocates that the supplied method
	// parameters were invalid
	// (https://www.jsonrpc.org/specification#error_object)
	ErrJSONRPCInvalidMethodParams = errors.New("Invalid method parameters")
	// ErrJSONRPCInternal indicates that an internal JSON-RPC error occurred
	// (https://www.jsonrpc.org/specification#error_object)
	ErrJSONRPCInternal = errors.New("Internal JSON-RPC Error")

	// ErrServerUnsupported indicates that unsupported
	// functionality was requested when initialising the Server object.
	ErrServerUnsupported = errors.New("Unsupported server functionality requested")
	// ErrServerInternal indicates that an unexpected internal error occurred
	ErrServerInternal = errors.New("Internal error occurred server-side")

	// ErrOPRFCiphersuiteUnsupportedFunction indicates that the given OPRF
	// function is not supported for the configuration specified by the
	// ciphersuite
	ErrOPRFCiphersuiteUnsupportedFunction = errors.New("Chosen OPRF function is not yet supported for the chosen ciphersuite")
	// ErrOPRFUnimplementedFunctionClient indicates that the function that has been
	// called is not implemented for the client in the OPRF protocol
	ErrOPRFUnimplementedFunctionClient = errors.New("Function is unimplemented for the OPRF client")
	// ErrOPRFUnimplementedFunctionServer indicates that the function that has been
	// called is not implemented for the server in the OPRF protocol
	ErrOPRFUnimplementedFunctionServer = errors.New("Function is unimplemented for the OPRF server")
	// ErrOPRFInvalidParticipant indicates that an internal error occurred
	// processing the participant of the OPRF protocol
	ErrOPRFInvalidParticipant = errors.New("Invalid protocol participant")

	// ErrUnsupportedGroup indicates that the requested group is not supported
	// the current implementation
	ErrUnsupportedGroup = errors.New("The chosen group is not supported")
	// ErrUnsupportedEE indicates that the requested ExtractorExpander is not
	// supported.
	ErrUnsupportedEE = errors.New("The chosen ExtractorExpander function is not supported, currently supported functions: [HKDF]")
	// ErrUnsupportedHash indicates that the requested function is not
	// supported.
	ErrUnsupportedHash = errors.New("The chosen hash function is not supported, currently supported functions: [SHA512]")
	// ErrUnsupportedH2C indicates that the requested hash-to-curve function is
	// not supported.
	ErrUnsupportedH2C = errors.New("The chosen hash-to-curve function is not supported, currently supported functions: [SSWU-RO (for NIST curves)]")
	// ErrIncompatibleGroupParams indicates that the requested group has a
	// parameter setting that is incompatible with our implementation
	ErrIncompatibleGroupParams = errors.New("The chosen group has an incompatible parameter setting")
	// ErrInvalidGroupElement indicates that the element in possession is not
	// a part of the expected group
	ErrInvalidGroupElement = errors.New("Group element is invalid")
	// ErrDeserializing indicates that the conversion of an octet-string into a
	// group element has failed
	ErrDeserializing = errors.New("Error deserializing group element from octet string")
	// ErrInternalInstantiation indicates that an error occurred when attempting to
	// instantiate the group
	ErrInternalInstantiation = errors.New("Internal error occurred with internal group instantiation")
	// ErrTypeAssertion indicates that type assertion has failed when attempting
	// to instantiate the OPRF interface
	ErrTypeAssertion = errors.New("Error attempting OPRF interface type assertion")
)

// ErrorJSON is a converted Error object for encoding errors into JSON
type ErrorJSON struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
}

// New creates a new ErrorJSON Object
func New(e error, code int) ErrorJSON {
	return ErrorJSON{Message: e.Error(), Code: code}
}

// GetJSONRPCError Parses the error that has occurred and creates a JSONRPC
// error response for the server to respond with
func GetJSONRPCError(e error) ErrorJSON {
	switch e {
	case ErrJSONRPCParse:
		return New(ErrJSONRPCParse, -32700)
	case ErrJSONRPCInvalidRequest:
		return New(ErrJSONRPCInvalidRequest, -32600)
	case ErrJSONRPCMethodNotFound:
		return New(ErrJSONRPCMethodNotFound, -32601)
	case ErrJSONRPCInternal:
		return New(ErrJSONRPCInternal, -32603)
	default:
		return New(ErrJSONRPCInvalidMethodParams, -32602)
	}
}
