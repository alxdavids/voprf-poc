extern crate voprf_rs;

use voprf_rs::http::client::start_client;
use voprf_rs::http::server::start_server;

use clap::{Arg,App};

fn main() {
    let matches = App::new("voprf-rs")
                        .version("0.0.1")
                        .author("alxdavids <coela@alxdavids.xyz>")
                        .about("Proof-of-concept implementation of draft-irtf-cfrg-voprf-02 in rust.")
                        .arg(Arg::with_name("group")
                            .long("group")
                            .required(true)
                            .takes_value(true)
                            .help("Sets the group to use, currently supported groups: P384, ristretto255 [EXPERIMENTAL]"))
                        .arg(Arg::with_name("mode")
                            .long("mode")
                            .required(true)
                            .takes_value(true)
                            .help("Determines the running mode, supported: server, client"))
                        .arg(Arg::with_name("port")
                            .long("port")
                            .default_value("3001")
                            .help("Sets the port number to use (default: 3001)"))
                        .arg(Arg::with_name("host")
                            .long("host")
                            .default_value("127.0.0.1")
                            .help("Sets the host name to use (default: 127.0.0.1)"))
                        .arg(Arg::with_name("pk")
                            .long("pk")
                            .takes_value(true)
                            .help("Sets the public key for the client (to be used in conjunction with a server running in verifiable mode)"))
                        .arg(Arg::with_name("verifiable")
                            .long("verifiable")
                            .help("Determines whether the ciphersuite should be verifiable or not"))
                        .arg(Arg::with_name("test")
                            .long("test")
                            .default_value("-1")
                            .help("Specifies whether the server is ran in test mode or not"))
                        .arg(Arg::with_name("n")
                            .long("n")
                            .default_value("3")
                            .help("Specifies the number of evaluations made by the client (default: 10)"))
                        .arg(Arg::with_name("max_evals")
                            .long("max_evals")
                            .default_value("10")
                            .help("Specifies the maximum number evaluations permitted on the server-side (default: 10)"))
                        .get_matches();

    let gp_name = matches.value_of("group").unwrap_or_else(|| panic!("no group selected")).to_string();
    let port = matches.value_of("port").unwrap_or("3001").to_string();
    let host = matches.value_of("host").unwrap_or("127.0.0.1").to_string();
    let n_evals = matches.value_of("n").unwrap().parse::<u16>().unwrap();
    let max_evals = matches.value_of("max_evals").unwrap().parse::<u16>().unwrap();
    let verifiable = matches.is_present("verifiable");
    let test_index = matches.value_of("test").unwrap().parse::<i16>().unwrap();
    let mode = matches.value_of("mode").unwrap_or_else(|| panic!("no mode selected"));
    match mode {
        "client" => {
            let mut pk = None;
            if verifiable && test_index == -1 {
                pk = Some(matches.value_of("pk").unwrap_or_else(|| panic!("Public key must be provided in verifiable mode")).to_string());
            }
            start_client(gp_name, host, port, None, pk, n_evals, verifiable, test_index)
        },
        "server" => start_server(gp_name, host, port, max_evals, verifiable, test_index),
        _ => panic!("unsupported mode specified {}", mode)
    }
}