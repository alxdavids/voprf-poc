//! The server module wraps the functionality required to run a HTTP server for
//! terminating (V)OPRF connections. The server is compatible with the go client
//! at https://github.com/alxdavids/voprf-poc/go. The supported ciphersuites
//! are: VOPRF-ristretto255-HKDF-SHA512-ELL2-RO (experimental) and
//! VOPRF-P384-HKDF-SHA512-SSWU-RO
//!
//! # Example commands
//!
//! * run P384 OPRF (not verifiable) with max_evals=10:
//!     `cargo run -- --group=P384 --mode=server --max_evals=10`
//! * run P384 VOPRF (verifiable):
//!     `cargo run -- --group=P384 --mode=server --max_evals=10 --verifiable`
//! * run P384 VOPRF using test vectors (verifiable), `test` can take values
//!   0..8 corresponding to the arrays found in test-vectors/:
//!     `cargo run -- --group=P384 --mode=server --max_evals=10 --test=1`
//! * running with the ristretto255 ciphersuite just requires changing `group`
//!   to `ristretto255`
use std::io::{Read,Error};
use std::marker::{Send,Sync};
use std::fs;

use rouille;
use rouille::{Response,ResponseBody};

use super::jsonrpc;
use jsonrpc::ErrorType;
use crate::oprf;
use oprf::ciphersuite::{Ciphersuite,Supported};
use oprf::groups::PrimeOrderGroup;
use oprf::Evaluation;
use oprf::groups::p384::NistPoint;
use oprf::groups::redox_ecc::{WPoint,MPoint};
use curve25519_dalek::ristretto::RistrettoPoint;

use sha2::Sha512;
use num::BigInt;
use num_bigint::Sign;
use serde::Deserialize;

/// The `Config` struct holds the necessary information for running the
/// (V)OPRF functionality as a HTTP server.
#[derive(Clone)]
pub struct Config<T,H>
        where T: Clone, H: Clone, T: Send + Sync {
    oprf_srv: oprf::Server<T,H>,
    host: String,
    port: String,
    max_evals: u16,
    tv: Option<TestVector>
}

impl<T,H> Config<T,H>
        where PrimeOrderGroup<T,H>: Supported, T: Clone + Send + Sync, H: Default
        + digest::Input + digest::BlockInput + digest::FixedOutput
        + digest::Reset + Clone {
    /// initialises the server config
    fn init(pog: PrimeOrderGroup<T,H>, host: String, port: String, max_evals: u16, verifiable: bool, test_idx: i16) -> Self {
        let ciph = Ciphersuite::new(pog, verifiable);
        let name = &ciph.name;
        let mut oprf_srv = oprf::Server::setup(ciph.clone());
        if max_evals > 100 {
            panic!("Max number of evals must be below 100")
        }

        let mut tv: Option<TestVector> = None;
        // indicates that the test mode is activated
        if test_idx != -1 {
            println!("***** Testing mode activated *****");
            // deserialize test vectors
            let tvs: Vec<TestVector> = serde_json::from_str(
                                &fs::read_to_string(
                                    format!("../test-vectors/{}.json", name)
                                ).unwrap()).unwrap();
            let t_vec = tvs[test_idx as usize].clone();
            // set new secret key
            oprf_srv.set_key(hex::decode(&t_vec.key).unwrap());
            tv = Some(t_vec);
            println!("Secret key: {}", oprf_srv.key.as_hex());
        }

        Self {
            oprf_srv: oprf_srv,
            host: host,
            port: port,
            max_evals: max_evals,
            tv: tv,
        }
    }
}

impl Config<NistPoint,Sha512> {
    fn p384_old(host: String, port: String, max_evals: u16, verifiable: bool, test_idx: i16) -> Self {
        let pog = PrimeOrderGroup::p384_old();
        Config::init(pog, host, port, max_evals, verifiable, test_idx)
    }
}

impl Config<RistrettoPoint,Sha512> {
    fn ristretto_255(host: String, port: String, max_evals: u16, verifiable: bool, test_idx: i16) -> Self {
        let pog = PrimeOrderGroup::ristretto_255();
        Config::init(pog, host, port, max_evals, verifiable, test_idx)
    }
}

impl Config<WPoint,Sha512> {
    fn p384(host: String, port: String, max_evals: u16, verifiable: bool, test_idx: i16) -> Self {
        let pog = PrimeOrderGroup::p384();
        Config::init(pog, host, port, max_evals, verifiable, test_idx)
    }
    fn p521(host: String, port: String, max_evals: u16, verifiable: bool, test_idx: i16) -> Self {
        let pog = PrimeOrderGroup::p521();
        Config::init(pog, host, port, max_evals, verifiable, test_idx)
    }
}

impl Config<MPoint,Sha512> {
    fn c448(host: String, port: String, max_evals: u16, verifiable: bool, test_idx: i16) -> Self {
        let pog = PrimeOrderGroup::c448();
        Config::init(pog, host, port, max_evals, verifiable, test_idx)
    }
}

/// Starts the HTTP server for processing VOPRF requests
pub fn start_server(group_name: String, host: String, port: String, max_evals: u16, verifiable: bool, test_index: i16) {
    match group_name.as_str() {
        "P384Old" => {
            let cfg = Config::p384_old(host, port, max_evals, verifiable, test_index);
            run(cfg);
        },
        "P384" => {
            let cfg = Config::p384(host, port, max_evals, verifiable, test_index);
            run(cfg);
        },
        "P521" => {
            let cfg = Config::p521(host, port, max_evals, verifiable, test_index);
            run(cfg);
        },
        "curve448" => {
            let cfg = Config::c448(host, port, max_evals, verifiable, test_index);
            run(cfg);
        },
        "ristretto255" => {
            let cfg = Config::ristretto_255(host, port, max_evals, verifiable, test_index);
            run(cfg);
        },
        _ => panic!("Unsupported group requested, supported groups are: 'P384Old', 'P384', 'P521', 'ristretto255'")
    }
}

/// Runs the `rouille` HTTP server for processing JSONRPC requests from (V)OPRF
/// clients.
///
/// Tried to include this function as part of the implementation of
/// `Config` but there were problems with lifetimes when trying to call
/// functions inside of the callback.
fn run<T,H>(cfg: Config<T,H>)
        where PrimeOrderGroup<T,H>: Supported, T: Clone + Send + Sync + 'static,
        H: Default + digest::Input + digest::BlockInput + digest::FixedOutput
        + digest::Reset + Clone + 'static {
    let ciph = &cfg.oprf_srv.ciph;
    println!("Server listening at {}:{} and running with ciphersuite {}", cfg.host, cfg.port, ciph.name);
    if ciph.verifiable {
        // output public key
        println!("Public key: {}", cfg.oprf_srv.key.pub_key(&ciph.pog).as_hex(&ciph.pog));
    }
    rouille::start_server(format!("{}:{}", cfg.host, cfg.port), move |request| {
        let data = request.data();
        match data {
            Some(mut body) => {
                let mut buf = Vec::new();
                match body.read_to_end(&mut buf) {
                    Ok(_) => process_request(&cfg, &buf),
                    Err(_) => {
                        println!("failed to process request");
                        let mut err_resp = Response::empty_400();
                        err_resp.data = ResponseBody::from_string(jsonrpc::error(ErrorType::ParseError, -1));
                        err_resp
                    }
                }
            },
            None => {
                println!("request data could not be read");
                let mut err_resp = Response::empty_400();
                err_resp.data = ResponseBody::from_string(jsonrpc::error(ErrorType::ParseError, -1));
                err_resp
            }
        }
    });
}

fn process_request<T,H>(cfg: &Config<T,H>, buf: &[u8]) -> Response
        where PrimeOrderGroup<T,H>: Supported, T: Clone + Send + Sync,
        H: Default + digest::Input + digest::BlockInput + digest::FixedOutput
        + digest::Reset + Clone {
    match jsonrpc::Request::read(buf) {
        Ok(req) => {
            let chosen_ciph = req.params.ciph;
            let srv = &cfg.oprf_srv;
            let srv_ciph = &srv.ciph;
            let id = req.id;
            // check that ciphersuite name matches
            if chosen_ciph != srv_ciph.name {
                println!("chosen ciphersuite ({}) is not the same as expected ({})", chosen_ciph, srv_ciph.name);
                let mut err_resp = Response::empty_400();
                err_resp.data = ResponseBody::from_string(jsonrpc::error(ErrorType::IncompatibleCiphersuite, id));
                return err_resp;
            }

            // attempt to deserialize group elements and process PRF evaluation
            let data = req.params.data;
            let pog = &srv_ciph.pog;
            let decoded: Result<Vec<Vec<u8>>, hex::FromHexError> = data.into_iter()
                .map(|s| hex::decode(s))
                .collect();
            let res: Result<Evaluation<T>, ErrorType> = match decoded {
                Ok(v) => {
                    let deser_eles: Result<Vec<T>, Error> = v.into_iter()
                                            .map(|bytes| (pog.deserialize)(&bytes))
                                            .collect();
                    match deser_eles {
                        // evaluate PRF
                        Ok(eles) => match &cfg.tv {
                            None => Ok(srv.eval(&eles)),
                            // if we're testing then we should evaluate with a
                            // fixed parameter for generating the DLEQ proof
                            Some(tv) => Ok(srv.fixed_eval(&eles, &hex::decode(&tv.dleq_scalar).unwrap())),
                        }
                        Err(_) => Err(ErrorType::Deserialization)
                    }
                },
                Err(_) => Err(ErrorType::InvalidParams)
            };

            // return evaluation results
            match res {
                Ok(ev) => {
                    // encode group elements
                    let mut buf = Vec::new();
                    let mut eles_hex = Vec::new();
                    for p in ev.elems {
                        (pog.serialize)(&p, true, &mut buf);
                        eles_hex.push(hex::encode(&buf));
                    }

                    // recover proof
                    let mut proof_hex = Vec::new();
                    if let Some(proof) = ev.proof {
                        proof_hex.push(hex::encode(&proof[0]));
                        proof_hex.push(hex::encode(&proof[1]));
                        // if we're testing then we should output the DLEQ value
                        // t that is used
                        if let Some(_) = &cfg.tv {
                            let c = BigInt::from_bytes_be(Sign::Plus, &proof[0]);
                            let s = BigInt::from_bytes_be(Sign::Plus, &proof[1]);
                            let k = BigInt::parse_bytes(&srv.key.as_hex().as_bytes(), 16).unwrap();
                            let (sgn, t) = (s+(c*k)).to_bytes_be();
                            let t_red = (pog.reduce_scalar)(&t, sgn == Sign::Plus);
                            println!("dleq scalar: {}", hex::encode(&t_red))
                        }
                    }
                    if proof_hex.len() != 2 && srv_ciph.verifiable {
                        // if the ciphersuite is verifiable, then we should have
                        // proof elements
                        println!("ciphersuite should be verifiable");
                        let mut err_resp = Response::empty_400();
                        err_resp.data = ResponseBody::from_string(jsonrpc::error(ErrorType::InternalError, id));
                        return err_resp;
                    }

                    // return successful evaluation
                    Response::text(jsonrpc::success(eles_hex, proof_hex, id))
                },
                Err(e) => {
                    println!("failed to process evaluation results");
                    let mut err_resp = Response::empty_400();
                    err_resp.data = ResponseBody::from_string(jsonrpc::error(e, id));
                    err_resp
                }
            }
        },
        Err(e) => {
            println!("failed to read request into buffer");
            let mut err_resp = Response::empty_400();
            err_resp.data = ResponseBody::from_string(jsonrpc::error(e, -1));
            err_resp
        }
    }
}

#[derive(Clone, Deserialize, Debug, PartialEq)]
struct TestVector {
    key: String,
    pub_key: String,
    dleq_scalar: String,
}

#[cfg(test)]
mod tests {
    use super::Config;
    use crate::oprf::groups::{PrimeOrderGroup,GroupID};
    use crate::oprf::{Client,Input,Evaluation};
    use crate::oprf::ciphersuite::Supported;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use crate::oprf::groups::p384::NistPoint;
    use crate::oprf::groups::redox_ecc::{WPoint,MPoint};
    use sha2::Sha512;

    #[test]
    fn init_oprf_ristretto() {
        let pog = PrimeOrderGroup::<RistrettoPoint,Sha512>::ristretto_255();
        init(pog, "OPRF-ristretto255-HKDF-SHA512-ELL2-RO", false, -1);
    }

    #[test]
    fn init_oprf_p384_old() {
        let pog = PrimeOrderGroup::<NistPoint,Sha512>::p384_old();
        init(pog, "OPRF-P384-HKDF-SHA512-SSWU-RO", false, -1);
    }

    #[test]
    fn init_oprf_p384() {
        let pog = PrimeOrderGroup::<WPoint,Sha512>::p384();
        init(pog, "OPRF-P384-HKDF-SHA512-SSWU-RO", false, -1);
    }

    #[test]
    fn init_oprf_p521() {
        let pog = PrimeOrderGroup::<WPoint,Sha512>::p521();
        init(pog, "OPRF-P521-HKDF-SHA512-SSWU-RO", false, -1);
    }

    #[test]
    fn init_oprf_c448() {
        let pog = PrimeOrderGroup::<MPoint,Sha512>::c448();
        init(pog, "OPRF-curve448-HKDF-SHA512-ELL2-RO", false, -1);
    }

    #[test]
    fn init_voprf_ristretto() {
        let pog = PrimeOrderGroup::<RistrettoPoint,Sha512>::ristretto_255();
        init(pog, "VOPRF-ristretto255-HKDF-SHA512-ELL2-RO", true, -1);
    }

    #[test]
    fn init_voprf_p384_old() {
        let pog = PrimeOrderGroup::<NistPoint,Sha512>::p384_old();
        init(pog, "VOPRF-P384-HKDF-SHA512-SSWU-RO", true, -1);
    }

    #[test]
    fn init_voprf_p384() {
        let pog = PrimeOrderGroup::<WPoint,Sha512>::p384();
        init(pog, "VOPRF-P384-HKDF-SHA512-SSWU-RO", true, -1);
    }

    #[test]
    fn init_voprf_p521() {
        let pog = PrimeOrderGroup::<WPoint,Sha512>::p521();
        init(pog, "VOPRF-P521-HKDF-SHA512-SSWU-RO", true, -1);
    }

    #[test]
    fn init_voprf_c448() {
        let pog = PrimeOrderGroup::<MPoint,Sha512>::c448();
        init(pog, "VOPRF-curve448-HKDF-SHA512-ELL2-RO", true, -1);
    }

    #[test]
    #[should_panic(expected = "No such file or directory")]
    fn init_oprf_ristretto_tv() {
        let pog = PrimeOrderGroup::<RistrettoPoint,Sha512>::ristretto_255();
        init(pog, "OPRF-ristretto255-HKDF-SHA512-ELL2-RO", false, 1);
    }

    #[test]
    #[should_panic(expected = "No such file or directory")]
    fn init_oprf_p384_old_tv() {
        let pog = PrimeOrderGroup::<NistPoint,Sha512>::p384_old();
        init(pog, "OPRF-P384-HKDF-SHA512-SSWU-RO", false, 1);
    }

    #[test]
    #[should_panic(expected = "No such file or directory")]
    fn init_oprf_p384_tv() {
        let pog = PrimeOrderGroup::<WPoint,Sha512>::p384();
        init(pog, "OPRF-P384-HKDF-SHA512-SSWU-RO", false, 1);
    }

    #[test]
    #[should_panic(expected = "No such file or directory")]
    fn init_oprf_p521_tv() {
        let pog = PrimeOrderGroup::<WPoint,Sha512>::p521();
        init(pog, "OPRF-P521-HKDF-SHA512-SSWU-RO", false, 1);
    }

    #[test]
    #[should_panic(expected = "No such file or directory")]
    fn init_oprf_c448_tv() {
        let pog = PrimeOrderGroup::<MPoint,Sha512>::c448();
        init(pog, "OPRF-curve448-HKDF-SHA512-ELL2-RO", false, 1);
    }

    #[test]
    #[should_panic(expected = "No such file or directory")]
    fn init_voprf_ristretto_tv() {
        let pog = PrimeOrderGroup::<RistrettoPoint,Sha512>::ristretto_255();
        init(pog, "VOPRF-ristretto255-HKDF-SHA512-ELL2-RO", true, 1);
    }

    #[test]
    fn init_voprf_p384_old_tv() {
        let pog = PrimeOrderGroup::<NistPoint,Sha512>::p384_old();
        init(pog, "VOPRF-P384-HKDF-SHA512-SSWU-RO", true, 1);
    }

    #[test]
    fn init_voprf_p384_tv() {
        let pog = PrimeOrderGroup::<WPoint,Sha512>::p384();
        init(pog, "VOPRF-P384-HKDF-SHA512-SSWU-RO", true, 1);
    }

    #[test]
    fn init_voprf_p521_tv() {
        let pog = PrimeOrderGroup::<WPoint,Sha512>::p521();
        init(pog, "VOPRF-P521-HKDF-SHA512-SSWU-RO", true, 1);
    }

    #[test]
    #[should_panic(expected = "No such file or directory")]
    fn init_voprf_c448_tv() {
        let pog = PrimeOrderGroup::<MPoint,Sha512>::c448();
        init(pog, "VOPRF-curve448-HKDF-SHA512-ELL2-RO", true, 1);
    }

    fn init<T,H>(pog: PrimeOrderGroup<T,H>, expected_name: &str, verifiable: bool, test_idx: i16)
            where  Input<T>: Clone, Evaluation<T>: Clone, T: Clone + Sync + Send, H: Clone
            + digest::BlockInput + digest::FixedOutput + digest::Input
            + digest::Reset + std::default::Default,
            PrimeOrderGroup<T, H>: Supported, Client<T,H>: Clone {
        let host = "some_host".to_string();
        let port = "1234".to_string();
        let max_evals = 5;
        let cfg = Config::init(pog.clone(), host.clone(), port.clone(), max_evals, verifiable, test_idx);
        assert_eq!(cfg.oprf_srv.ciph.verifiable, verifiable);
        assert_eq!(cfg.oprf_srv.ciph.name, expected_name);
        assert_eq!(cfg.host, host);
        assert_eq!(cfg.port, port);
        assert_eq!(cfg.max_evals, max_evals);
        match test_idx {
            -1 => {
                if let Some(_) = cfg.tv {
                    panic!("Test vectors should not be being used");
                }
            },
            _ => {
                if let None = cfg.tv {
                    panic!("Test vectors should be being used");
                } else if let Some(tv) = cfg.tv {
                    match &pog.group_id {
                        GroupID::P384Old | GroupID::P384 => {
                            assert_eq!(tv.key, "e03aa64d63cee2619a115eaa935078020a1c79634afaa163d867061a68b9bd7eb821badf2d1a725263fc11e4c712c40a".to_string());
                            assert_eq!(tv.pub_key, "030f290e5d9ec013f30968a4db66f36c20fd204a06bb8edf805a1936af744acde2f906f7190f2c206516fc49d23c65a424".to_string());
                            assert_eq!(tv.dleq_scalar, "7e9d53e392518f0f7ec1ae1189ac5165288aa242849127a60764fd72b7f394c5d2f014830c18359000eb0f3e50815ae6".to_string());
                        },
                        GroupID::P521 => {
                            assert_eq!(tv.key, "c158c753df6d52138f2dc5e64f97e5c7fe79cc8d7221fd902e3985eecc3c088c8361fa828b857253bfdbff493aaa0ba9f778e8d7c61df6f322da2bae44693c17d2".to_string());
                            assert_eq!(tv.pub_key, "03013c276714a1b26b857a61c066246d8ae155b29b98c66ab6c10996e23199272a132ceb0bdba4d1423792720d9c67f9fff86a22f613e7eba65b04ce6911513d2252ec".to_string());
                            assert_eq!(tv.dleq_scalar, "01dd8eaa7063373873017281198537cf59b3bcbc4738e35d124a09ddd7ca2929af0bad76d1ee3e826030b93b411abe238ff2d8dfff777db422233ff5731b8dc14500".to_string());
                        },
                        _ => panic!("Unsupported group")
                    }
                }
            }
        }
    }
}