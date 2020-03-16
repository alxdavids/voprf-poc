//! jsonrpc mod

use serde::{Serialize,Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Request {
    pub jsonrpc: String,
    pub method: String,
    pub params: RequestParams,
    pub id: i16,
}

impl Request {
    pub fn read(body: &[u8]) -> Result<Request, ErrorType> {
        let req: Request = serde_json::from_slice(body).unwrap();
        match req.validate() {
            Ok(()) => Ok(req),
            Err(e) => Err(e)
        }
    }

    fn validate(&self) -> Result<(), ErrorType> {
        match self.jsonrpc.as_str() {
            "2.0" => match self.method.as_str() {
                "eval" => {
                    if self.params.data.len() < 1 {
                        return Err(ErrorType::InvalidParams);
                    }
                    Ok(())
                },
                _ => Err(ErrorType::MethodNotFound),
            },
            _ => Err(ErrorType::InvalidRequest)
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RequestParams {
    pub data: Vec<String>,
    pub ciph: String
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ResponseSuccess {
    pub jsonrpc: String,
    pub result: SuccessResult,
    pub id: i16
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SuccessResult {
    pub data: Vec<String>,
    pub proof: Vec<String>,
}

pub fn success(data: Vec<String>, proof: Vec<String>, id: i16) -> String {
    let result = SuccessResult{ data: data, proof: proof };
    let resp = ResponseSuccess{ jsonrpc: "2.0".to_string(), result: result, id: id };
    serde_json::to_string(&resp).unwrap()
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ResponseError {
    pub jsonrpc: String,
    pub error: ErrorResult,
    pub id: i16,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ErrorResult {
    pub message: String,
    pub code: i16,
}

pub enum ErrorType {
    ParseError,
    InvalidRequest,
    MethodNotFound,
    InvalidParams,
    InternalError,
    // custom JSON-RPC errors
    IncompatibleCiphersuite,
    Deserialization,
}

pub fn error(err: ErrorType, id: i16) -> String {
    let result = match err {
        ErrorType::ParseError => ErrorResult{ message: "Invalid JSON was received by the server. An error occurred on the server while parsing the JSON text.".to_string(), code: -32700 },
        ErrorType::InvalidRequest => ErrorResult{ message: "The JSON sent is not a valid Request object.".to_string(), code: -32600 },
        ErrorType::MethodNotFound => ErrorResult{ message: "The method does not exist / is not available.".to_string(), code: -32601 },
        ErrorType::InvalidParams => ErrorResult{ message: "Invalid method parameter(s).".to_string(), code: -32602 },
        ErrorType::IncompatibleCiphersuite => ErrorResult{ message: "Specified ciphersuite is incompatible with server.".to_string(), code: -32000 },
        ErrorType::Deserialization => ErrorResult{ message: "Failed to deserialize client input.".to_string(), code: -32001 },
        _ => {
            ErrorResult{ message: "Internal JSON-RPC error.".to_string(), code: -32603 }
        },
    };
    let resp_err = ResponseError{ jsonrpc: "2.0".to_string(), error: result, id: id };
    serde_json::to_string(&resp_err).unwrap()
}