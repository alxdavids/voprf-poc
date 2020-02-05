//! Collection of (V)OPRF specific errors

use std::io::{Error, ErrorKind};

/// Error deserializing bytes into a valid group element object
pub fn err_deserialization() -> Error { Error::new(ErrorKind::Other, "Failed to deserialize") }

/// Indicates that the client has no valid public key set
pub fn err_public_key_not_found() -> Error { Error::new(ErrorKind::Other, "No public key found for verification") }
/// Indicates that the server response does not contain a proof object, when one
/// was expected
pub fn err_proof_not_found() -> Error { Error::new(ErrorKind::Other, "No proof object sent for verification") }
/// Indicates that client proof verification failed based on the server response
pub fn err_proof_verification() -> Error { Error::new(ErrorKind::Other, "Proof verification failed") }

/// Indicates that the client failed to process finalization of the (V)OPRF
/// output
pub fn err_finalization() -> Error { Error::new(ErrorKind::Other, "Finalization failed") }

/// Indicates that an internal error occurred
pub fn err_internal() -> Error { Error::new(ErrorKind::Other, "Internal error occurred") }