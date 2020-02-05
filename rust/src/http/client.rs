//! client module
use std::fs;

use reqwest;

use super::jsonrpc;
use crate::oprf;
use oprf::ciphersuite::{Ciphersuite,Supported};
use oprf::groups::PrimeOrderGroup;
use oprf::groups::p384::NistPoint;
use curve25519_dalek::ristretto::RistrettoPoint;
use sha2::Sha512;

use serde::Deserialize;

const AUX_DATA: &str = "oprf_finalization_step";

/// The `Config` struct contains the data necessary for running a (V)OPRF client
/// over HTTP
pub struct Config<T,H>
        where T: Clone, H: Clone {
    oprf_cli: oprf::Client<T,H>,
    host: String,
    port: String,
    n_evals: u16,
    verifiable: bool,
    out_path: Option<String>,
    tv: Option<TestVector>,
}

impl<T,H> Config<T,H>
        where PrimeOrderGroup<T,H>: Supported, T: Clone + Send + Sync, H: Default
        + digest::Input + digest::BlockInput + digest::FixedOutput
        + digest::Reset + Clone {
    /// initialises the client config
    fn init(pog: PrimeOrderGroup<T,H>, host: String, port: String,
            out_path: Option<String>, pub_key: Option<String>, n_evals: u16,
            verifiable: bool, test_idx: i16) -> Self {
        let ciph = Ciphersuite::new(pog.clone(), verifiable);

        let mut tv: Option<TestVector> = None;
        let mut pk_to_use = pub_key;
        // indicates that the test mode is activated
        if test_idx != -1 {
            println!("***** Testing mode activated *****");
            // deserialize test vectors
            let tvs: Vec<TestVector> = serde_json::from_str(
                            &fs::read_to_string(
                                format!("../test_vectors/{}.json", ciph.name)
                            ).unwrap()).unwrap();
            let t_vec = tvs[test_idx as usize].clone();
            pk_to_use = Some(t_vec.pub_key.clone());
            tv = Some(t_vec);
        }

        let pk = match pk_to_use {
            Some(s) => Some(oprf::PublicKey::from_hex(s, &pog)),
            None => None,
        };

        // print out Public key being used for debugging
        if let Some(val) = &pk {
            println!("Public key: {}", val.as_hex(&pog));
        }

        // Run (V)OPRF setup
        let oprf_cli = oprf::Client::setup(ciph, pk).unwrap();
        if n_evals > 100 {
            panic!("Max number of evals must be below 100")
        }
        Self {
            oprf_cli: oprf_cli,
            host: host,
            port: port,
            n_evals: n_evals,
            verifiable: verifiable,
            out_path: out_path,
            tv: tv,
        }
    }
}

impl Config<NistPoint,Sha512> {
    fn p384(host: String, port: String, out_path: Option<String>,
            pub_key: Option<String>, n_evals: u16, verifiable: bool, test_idx: i16) -> Self {
        let pog = PrimeOrderGroup::p384();
        Config::init(pog, host, port, out_path, pub_key, n_evals, verifiable, test_idx)
    }
}

impl Config<RistrettoPoint,Sha512> {
    fn ristretto_255(host: String, port: String, out_path: Option<String>,
            pub_key: Option<String>, n_evals: u16, verifiable: bool, test_idx: i16) -> Self {
        let pog = PrimeOrderGroup::ristretto_255();
        Config::init(pog, host, port, out_path, pub_key, n_evals, verifiable, test_idx)
    }
}

/// Starts the HTTP client for sending VOPRF messages
pub fn start_client(group_name: String, host: String, port: String,
        out_path: Option<String>, pub_key: Option<String>, n_evals: u16,
        verifiable: bool, test_idx: i16) {
    match group_name.as_str() {
        "P384" => {
            let cfg = Config::p384(host, port, out_path, pub_key, n_evals, verifiable, test_idx);
            run(cfg);
        },
        "ristretto255" => {
            let cfg = Config::ristretto_255(host, port, out_path, pub_key, n_evals, verifiable, test_idx);
            run(cfg);
        },
        _ => panic!("Unsupported group requested, supported groups are: 'P384', 'ristretto255'")
    }
}

/// Runs the `rouille` HTTP client for constructing JSONRPC requests as a
/// (V)OPRF client.
fn run<T,H>(cfg: Config<T,H>)
        where PrimeOrderGroup<T,H>: Supported, T: Clone + Send + Sync + 'static,
        H: Default + digest::Input + digest::BlockInput + digest::FixedOutput
        + digest::Reset + Clone + 'static {
    let ciph = &cfg.oprf_cli.ciph;
    let pog = &ciph.pog;
    let target = format!("http://{}:{}", cfg.host, cfg.port);
    println!("Client attempting to connect to {} and running with ciphersuite {}", target, ciph.name);

    // generate inputs
    let oprf_inputs = generate_inputs(&cfg);
    let mut enc_elems = Vec::new();
    for inp in &oprf_inputs {
        let ele = &inp.elem;
        let mut buf = Vec::new();
        (pog.serialize)(ele, true, &mut buf);
        enc_elems.push(hex::encode(buf));
    }

    // construct and serialize JSON-RPC request
    let req = jsonrpc::Request {
        jsonrpc: String::from("2.0"),
        method: String::from("eval"),
        params: jsonrpc::RequestParams {
            data: enc_elems,
            ciph: ciph.name.clone(),
        },
        id: 1
    };
    let req_data = serde_json::to_string(&req).unwrap();

    // Send post request
    let client = reqwest::blocking::Client::new();
    let resp = client.post(target.as_str()).body(req_data).send().unwrap();
    let (final_outs, srv_data, srv_proof) = process_resp(&cfg, resp, &oprf_inputs);
    write_outputs(&cfg, &oprf_inputs, &srv_data, &srv_proof, &final_outs);
}

fn generate_inputs<T,H>(cfg: &Config<T,H>) -> Vec<oprf::Input<T>>
        where PrimeOrderGroup<T,H>: Supported, T: Clone + Send + Sync + 'static,
        H: Default + digest::Input + digest::BlockInput + digest::FixedOutput
        + digest::Reset + Clone + 'static {
    let mut out = Vec::new();
    let pog = &cfg.oprf_cli.ciph.pog;
    if let Some(v) = &cfg.tv {
        // ues test vector inputs
        let inputs = &v.inputs;
        let blinds = &v.blinds;
        for i in 0..inputs.len() {
            // if not in test mode, then generate bytes uniformly
            let x = hex::decode(&inputs[i]).unwrap();
            let r = hex::decode(&blinds[i]).unwrap();
            let ele = cfg.oprf_cli.blind_fixed(&x, &r);
            // generate Input object
            out.push(
                oprf::Input {
                    data: x,
                    elem: ele,
                    blind: r
                }
            )
        }
    } else {
        // generate inputs randomly
        let mut inputs: Vec<Vec<u8>> = Vec::new();
        let mut buf = Vec::new();
        for _ in 0..cfg.n_evals {
            (pog.uniform_bytes)(&mut buf);
            inputs.push(buf.clone());
        }
        out = cfg.oprf_cli.blind(&inputs);
    }
    out
}

fn process_resp<T,H>(cfg: &Config<T,H>, resp: reqwest::blocking::Response,
            oprf_inputs: &[oprf::Input<T>]) -> (Vec<Vec<u8>>, Vec<String>, Vec<String>)
        where PrimeOrderGroup<T,H>: Supported, T: Clone + Send + Sync + 'static,
        H: Default + digest::Input + digest::BlockInput + digest::FixedOutput
        + digest::Reset + Clone + 'static {
    if !resp.status().is_success() {
        let j_err: jsonrpc::ResponseError = resp.json().unwrap();
        panic!("Error occurred, message: {}, code: {}", j_err.error.message, j_err.error.code);
    }

    // recover output result
    let out: jsonrpc::ResponseSuccess = resp.json().unwrap();
    let result = out.result;
    if result.data.len() != oprf_inputs.len() {
        panic!("Length of input vector does not match response vector");
    }

    // parse group elements from data
    let oprf_cli = &cfg.oprf_cli;
    let pog = &oprf_cli.ciph.pog;
    let mut elems = Vec::new();
    for z in &result.data {
        elems.push((pog.deserialize)(&hex::decode(&z).unwrap()).unwrap());
    }

    // parse proof
    let mut proof: Option<[Vec<u8>; 2]> = None;
    if cfg.verifiable {
        if result.proof.len() != 2 {
            panic!("Invalid proof object returned by server");
        }
        proof = Some([hex::decode(&result.proof[0]).unwrap(), hex::decode(&result.proof[1]).unwrap()]);
    }

    // create Evaluation object & unblind
    let oprf_eval = oprf::Evaluation {
        elems: elems,
        proof: proof
    };
    let finals = match oprf_cli.unblind(oprf_inputs, &oprf_eval) {
        Ok(outs) => {
            let aux = AUX_DATA.as_bytes();
            let mut finals = Vec::new();
            for i in 0..outs.len() {
                let x = &oprf_inputs[i].data;
                let eval = &outs[i];
                // finalize outputs
                let o = match oprf_cli.finalize(x, eval, &aux) {
                    Ok(o) => o,
                    Err(e) => panic!("Error occurred when finalizing: {:?}", e)
                };
                finals.push(o);
            }
            finals
        }
        Err(e) => panic!("Error occurred when unblinding: {:?}", e)
    };
    // output other data for debugging purposes
    (finals, result.data, result.proof)
}

fn write_outputs<T,H>(cfg: &Config<T,H>, inputs: &[oprf::Input<T>],
            eval_elems: &[String], proof_vals: &[String], outputs: &[Vec<u8>])
        where PrimeOrderGroup<T,H>: Supported, T: Clone + Send + Sync + 'static,
        H: Default + digest::Input + digest::BlockInput + digest::FixedOutput
        + digest::Reset + Clone + 'static {
    let mut data = Vec::new();
    let mut blind = Vec::new();
    let mut finals = Vec::new();
    for i in 0..inputs.len() {
        data.push(hex::encode(&inputs[i].data));
        blind.push(hex::encode(&inputs[i].blind));
        finals.push(hex::encode(&outputs[i]));
    }
    let data_join =  data.join(",\n");
    let blind_join = blind.join(",\n");
    let final_join =  finals.join(",\n");
    let elems_join = eval_elems.join(",\n");
    let proof_join = proof_vals.join(",\n");

    // write output strings
    let out_strings = vec![data_join, blind_join, final_join, elems_join, proof_join];
    if let Some(path) = &cfg.out_path {
    let file_names = vec!["stored_inputs.txt", "stored_blinds.txt", "stored_final_outputs.txt", "stored_eval_elems.txt", "stored_proof.txt"];
        for i in 0..file_names.len() {
            fs::write(format!("{}/{}", path, file_names[i]), out_strings[i].as_bytes()).unwrap();
        }
    } else {
        let headers = vec!["Inputs", "Blinds", "Outputs", "Evaluated elements", "Proof values"];
        for i in 0..headers.len() {
            println!("***********");
            println!("{}", headers[i]);
            println!("===========");
            println!("{}", out_strings[i]);
            println!("***********");
        }
    }
}

#[derive(Clone, Deserialize, Debug)]
struct TestVector {
    pub_key: String,
    inputs: Vec<String>,
    blinds: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::Config;
    use crate::oprf::groups::PrimeOrderGroup;
    use crate::oprf::{Client,Input,Evaluation};
    use crate::oprf::ciphersuite::Supported;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use crate::oprf::groups::p384::NistPoint;
    use sha2::Sha512;

    #[test]
    fn init_oprf_ristretto() {
        let pog = PrimeOrderGroup::<RistrettoPoint,Sha512>::ristretto_255();
        init(pog, "OPRF-ristretto255-HKDF-SHA512-ELL2-RO", None, false, -1);
    }

    #[test]
    fn init_oprf_p384() {
        let pog = PrimeOrderGroup::<NistPoint,Sha512>::p384();
        init(pog, "OPRF-P384-HKDF-SHA512-SSWU-RO", None, false, -1);
    }

    #[test]
    #[should_panic(expected = "No public key found")]
    fn init_voprf_ristretto_no_pub_key() {
        let pog = PrimeOrderGroup::<RistrettoPoint,Sha512>::ristretto_255();
        init(pog, "VOPRF-ristretto255-HKDF-SHA512-ELL2-RO", None, true, -1);
    }

    #[test]
    #[should_panic(expected = "No public key found")]
    fn init_voprf_p384_no_pub_key() {
        let pog = PrimeOrderGroup::<NistPoint,Sha512>::p384();
        init(pog, "VOPRF-P384-HKDF-SHA512-SSWU-RO", None, true, -1);
    }

    #[test]
    fn init_voprf_ristretto() {
        let pog = PrimeOrderGroup::<RistrettoPoint,Sha512>::ristretto_255();
        init(pog, "VOPRF-ristretto255-HKDF-SHA512-ELL2-RO", Some("d8d3fd409a2a206295f5c8f840a12f0ce41aefe7d3b72b6246d72ee01649cf45".to_string()), true, -1);
    }

    #[test]
    fn init_voprf_p384() {
        let pog = PrimeOrderGroup::<NistPoint,Sha512>::p384();
        init(pog, "VOPRF-P384-HKDF-SHA512-SSWU-RO", Some("025f59ac8471663cc47be651b3e4315467aff9ec595a82d65fb7b11c33ca0e387c0238299040e2c7ae852795b0696d987c".to_string()), true, -1);
    }

    #[test]
    #[should_panic(expected = "No such file or directory")]
    fn init_oprf_ristretto_tv() {
        let pog = PrimeOrderGroup::<RistrettoPoint,Sha512>::ristretto_255();
        init(pog, "OPRF-ristretto255-HKDF-SHA512-ELL2-RO", None, false, 1);
    }

    #[test]
    #[should_panic(expected = "No such file or directory")]
    fn init_oprf_p384_tv() {
        let pog = PrimeOrderGroup::<NistPoint,Sha512>::p384();
        init(pog, "OPRF-P384-HKDF-SHA512-SSWU-RO", None, false, 1);
    }

    #[test]
    #[should_panic(expected = "No such file or directory")]
    fn init_voprf_ristretto_tv() {
        let pog = PrimeOrderGroup::<RistrettoPoint,Sha512>::ristretto_255();
        init(pog, "VOPRF-ristretto255-HKDF-SHA512-ELL2-RO", None, true, 1);
    }

    #[test]
    fn init_voprf_p384_tv() {
        let pog = PrimeOrderGroup::<NistPoint,Sha512>::p384();
        init(pog, "VOPRF-P384-HKDF-SHA512-SSWU-RO", None, true, 1);
    }

    fn init<T,H>(pog: PrimeOrderGroup<T,H>, expected_name: &str, pub_key: Option<String>, verifiable: bool, test_idx: i16)
            where  Input<T>: Clone, Evaluation<T>: Clone, T: Clone + Sync + Send, H: Clone
            + digest::BlockInput + digest::FixedOutput + digest::Input
            + digest::Reset + std::default::Default,
            PrimeOrderGroup<T, H>: Supported, Client<T,H>: Clone {
        let host = "some_host".to_string();
        let port = "1234".to_string();
        let out_path = Some("some_file_path".to_string());
        let n_evals = 5;
        let cfg = Config::init(pog.clone(), host.clone(), port.clone(), out_path.clone(), pub_key.clone(), n_evals, verifiable, test_idx);
        assert_eq!(cfg.oprf_cli.ciph.verifiable, verifiable);
        assert_eq!(cfg.oprf_cli.ciph.name, expected_name);
        assert_eq!(cfg.host, host);
        assert_eq!(cfg.port, port);
        assert_eq!(cfg.n_evals, n_evals);
        match pub_key {
            None => {
                if let Some(_) = cfg.oprf_cli.key {
                    if test_idx == -1 {
                        panic!("Public key should be null");
                    }
                }
            },
            Some(pk) => {
                if let None = cfg.oprf_cli.key {
                    panic!("Public key should be set");
                }
                assert_eq!(pk, cfg.oprf_cli.key.unwrap().as_hex(&pog));
            },
        };
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
                    assert_eq!(tv.pub_key, "030f290e5d9ec013f30968a4db66f36c20fd204a06bb8edf805a1936af744acde2f906f7190f2c206516fc49d23c65a424".to_string());
                    assert_eq!(tv.inputs.len(), 8);
                    assert_eq!(tv.blinds.len(), 8);
                }
            }
        }
    }
}