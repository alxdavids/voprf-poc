package oerr

import "errors"

var (
	// ErrServerUnsupportedFunctionality indicates that unsupported
	// functionality was requested when initialising the Server object.
	ErrServerUnsupportedFunctionality = Error{message: errors.New("Unsupported server functionality requested"), code: -32000}
	// ErrClientMalformedRequest indicates that the request sent by the client
	// cannot be processed due to malformation
	ErrClientMalformedRequest = Error{message: errors.New("Client request is malformed"), code: -32001}

	// ErrOPRFCiphersuiteUnsupportedFunction indicates that the given OPRF
	// function is not supported for the configuration specified by the
	// ciphersuite
	ErrOPRFCiphersuiteUnsupportedFunction = Error{message: errors.New("Chosen OPRF function is not yet supported for the chosen ciphersuite"), code: -32020}
	// ErrOPRFUnimplementedFunctionClient indicates that the function that has been
	// called is not implemented for the client in the OPRF protocol
	ErrOPRFUnimplementedFunctionClient = Error{message: errors.New("Function is unimplemented for the OPRF client"), code: -32021}
	// ErrOPRFUnimplementedFunctionServer indicates that the function that has been
	// called is not implemented for the server in the OPRF protocol
	ErrOPRFUnimplementedFunctionServer = Error{message: errors.New("Function is unimplemented for the OPRF server"), code: -32022}
	// ErrOPRFInvalidParticipant indicates that an internal error occurred
	// processing the participant of the OPRF protocol
	ErrOPRFInvalidParticipant = Error{message: errors.New("Invalid protocol participant"), code: -32023}

	// ErrUnsupportedGroup indicates that the requested group is not supported
	// the current implementation
	ErrUnsupportedGroup = Error{message: errors.New("The chosen group is not supported"), code: -32020}
	// ErrUnsupportedEE indicates that the requested ExtractorExpander is not
	// supported.
	ErrUnsupportedEE = Error{message: errors.New("The chosen ExtractorExpander function is not supported, currently supported functions: [HKDF]"), code: -32041}
	// ErrUnsupportedHash indicates that the requested function is not
	// supported.
	ErrUnsupportedHash = Error{message: errors.New("The chosen hash function is not supported, currently supported functions: [SHA512]"), code: -32042}
	// ErrUnsupportedH2C indicates that the requested hash-to-curve function is
	// not supported.
	ErrUnsupportedH2C = Error{message: errors.New("The chosen hash-to-curve function is not supported, currently supported functions: [SSWU-RO (for NIST curves)]"), code: -32043}
	// ErrIncompatibleGroupParams indicates that the requested group has a
	// parameter setting that is incompatible with our implementation
	ErrIncompatibleGroupParams = Error{message: errors.New("The chosen group has an incompatible parameter setting"), code: -32044}
	// ErrInvalidGroupElement indicates that the element in possession is not
	// a part of the expected group
	ErrInvalidGroupElement = Error{message: errors.New("Group element is invalid"), code: -32045}
	// ErrDeserializing indicates that the conversion of an octet-string into a
	// group element has failed
	ErrDeserializing = Error{message: errors.New("Error deserializing group element from octet string"), code: -32046}
	// ErrInternalInstantiation indicates that an error occurred when attempting to
	// instantiate the group
	ErrInternalInstantiation = Error{message: errors.New("Internal error occurred with internal group instantiation"), code: -32047}
	// ErrTypeAssertion indicates that type assertion has failed when attempting
	// to instantiate the OPRF interface
	ErrTypeAssertion = Error{message: errors.New("Error attempting OPRF interface type assertion"), code: -32048}
)

// Error is a wrapper around a traditional error object for specifying error
// codes in the OPRF protocol
type Error struct {
	message error
	code    int
}

// Err returns the error type associated with the Error object
func (e Error) Err() error { return e.message }

// Code returns the int error code associated with the Error object
func (e Error) Code() int { return e.code }

// New returns a new Error object with the supplied message and error code
func New(message string, code int) Error {
	return Error{message: errors.New(message), code: code}
}

// Nil returns a nil Error object
func Nil() Error {
	return Error{}
}
