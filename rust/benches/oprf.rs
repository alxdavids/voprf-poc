use criterion::{black_box, criterion_group, criterion_main, Criterion};
use voprf_rs::oprf::*;
use voprf_rs::oprf::Server;
use voprf_rs::oprf::groups::PrimeOrderGroup;
use voprf_rs::oprf::ciphersuite::{Ciphersuite,Supported};

fn server_oprf_setup_ristretto() {
    let pog = PrimeOrderGroup::ristretto_255();
    let ciph = Ciphersuite::new(pog, false);
    Server::setup(ciph);
}

fn server_voprf_setup_ristretto() {
    let pog = PrimeOrderGroup::ristretto_255();
    let ciph = Ciphersuite::new(pog, true);
    Server::setup(ciph);
}

fn server_oprf_setup_p384() {
    let pog = PrimeOrderGroup::p384();
    let ciph = Ciphersuite::new(pog, false);
    Server::setup(ciph);
}

fn server_voprf_setup_p384() {
    let pog = PrimeOrderGroup::p384();
    let ciph = Ciphersuite::new(pog, true);
    Server::setup(ciph);
}

fn server_eval<T,H>(srv: Server<T,H>, elems: &[T]) -> Evaluation<T>
        where Input<T>: Clone, Evaluation<T>: Clone, T: Clone, H: Clone
        + digest::BlockInput + digest::FixedOutput + digest::Input
        + digest::Reset + std::default::Default,
        PrimeOrderGroup<T, H>: Supported, Server<T,H>: Clone {
    srv.eval(elems)
}

fn client_oprf_setup_ristretto() {
    let pog = PrimeOrderGroup::ristretto_255();
    let ciph = Ciphersuite::new(pog, false);
    Client::setup(ciph, None).unwrap();
}

fn client_voprf_setup_ristretto(pub_key: String) {
    let pog = PrimeOrderGroup::ristretto_255();
    let ciph = Ciphersuite::new(pog.clone(), true);
    Client::setup(ciph, Some(PublicKey::from_hex(pub_key, &pog))).unwrap();
}

fn client_oprf_setup_p384() {
    let pog = PrimeOrderGroup::p384();
    let ciph = Ciphersuite::new(pog, false);
    Client::setup(ciph, None).unwrap();
}

fn client_voprf_setup_p384(pub_key: String) {
    let pog = PrimeOrderGroup::p384();
    let ciph = Ciphersuite::new(pog.clone(), true);
    Client::setup(ciph, Some(PublicKey::from_hex(pub_key, &pog))).unwrap();
}

fn client_blind<T,H>(cli: Client<T,H>, x: Vec<u8>) -> Vec<Input<T>>
        where  Input<T>: Clone, Evaluation<T>: Clone, T: Clone, H: Clone
        + digest::BlockInput + digest::FixedOutput + digest::Input
        + digest::Reset + std::default::Default,
        PrimeOrderGroup<T, H>: Supported, Client<T,H>: Clone {
    cli.blind(&vec![x])
}

fn client_unblind<T,H>(cli: Client<T,H>, inputs: Vec<Input<T>>, evals: Evaluation<T>) -> Vec<T>
        where  Input<T>: Clone, Evaluation<T>: Clone, T: Clone, H: Clone
        + digest::BlockInput + digest::FixedOutput + digest::Input
        + digest::Reset + std::default::Default,
        PrimeOrderGroup<T, H>: Supported, Client<T,H>: Clone {
    cli.unblind(&inputs, &evals).unwrap()
}

fn client_finalize<T,H>(cli: Client<T,H>, x: &[u8], unblinded: &T, aux: &[u8])
        where  Input<T>: Clone, Evaluation<T>: Clone, T: Clone, H: Clone
        + digest::BlockInput + digest::FixedOutput + digest::Input
        + digest::Reset + std::default::Default,
        PrimeOrderGroup<T, H>: Supported, Client<T,H>: Clone {
    cli.finalize(x, unblinded, aux).unwrap();
}

fn create_unblinding_values<T,H>(ciph: Ciphersuite<T,H>, inputs: &[Vec<u8>]) -> (Client<T,H>, Vec<Input<T>>, Evaluation<T>)
        where  Input<T>: Clone, Evaluation<T>: Clone, T: Clone, H: Clone
        + digest::BlockInput + digest::FixedOutput + digest::Input
        + digest::Reset + std::default::Default,
        PrimeOrderGroup<T, H>: Supported, Client<T,H>: Clone {
    let srv = Server::setup(ciph.clone());
    let cli = Client::setup(ciph.clone(), Some(srv.key.pub_key(&ciph.pog))).unwrap();
    let blinded_inps = cli.blind(inputs);
    let mut elems = Vec::new();
    for bi in &blinded_inps {
        elems.push(bi.elem.clone());
    }
    (cli, blinded_inps, srv.eval(&elems))
}

fn criterion_benchmark(c: &mut Criterion) {
    /******************** SERVER BENCHMARKS ********************/

    // setup
    c.bench_function("srv setup oprf ristretto", |b| b.iter(|| server_oprf_setup_ristretto()));
    c.bench_function("srv setup voprf ristretto", |b| b.iter(|| server_oprf_setup_p384()));
    c.bench_function("srv setup oprf p384", |b| b.iter(|| server_voprf_setup_ristretto()));
    c.bench_function("srv setup voprf p384", |b| b.iter(|| server_voprf_setup_p384()));

    // non-batched eval
    c.bench_function("srv eval oprf ristretto n=1", |b| {
        let pog = PrimeOrderGroup::ristretto_255();
        let ele = (pog.clone().random_element)();
        let ciph = Ciphersuite::new(pog, false);
        let srv = Server::setup(ciph);
        b.iter(|| server_eval(black_box(srv.clone()), black_box(&vec![ele.clone()])))
    });
    c.bench_function("srv eval voprf ristretto n=1", |b| {
        let pog = PrimeOrderGroup::ristretto_255();
        let ele = (pog.clone().random_element)();
        let ciph = Ciphersuite::new(pog, true);
        let srv = Server::setup(ciph);
        b.iter(|| server_eval(black_box(srv.clone()), black_box(&vec![ele.clone()])))
    });
    c.bench_function("srv eval oprf p384 n=1", |b| {
        let pog = PrimeOrderGroup::p384();
        let ele = (pog.clone().random_element)();
        let ciph = Ciphersuite::new(pog, false);
        let srv = Server::setup(ciph);
        b.iter(|| server_eval(black_box(srv.clone()), black_box(&vec![ele.clone()])))
    });
    c.bench_function("srv eval voprf p384 n=1", |b| {
        let pog = PrimeOrderGroup::p384();
        let ele = (pog.clone().random_element)();
        let ciph = Ciphersuite::new(pog, true);
        let srv = Server::setup(ciph);
        b.iter(|| server_eval(black_box(srv.clone()), black_box(&vec![ele.clone()])))
    });

    // n=5
    c.bench_function("srv eval oprf ristretto n=5", |b| {
        let pog = PrimeOrderGroup::ristretto_255();
        let mut elems = Vec::new();
        for _ in 0..5 {
            elems.push((pog.clone().random_element)());
        }
        let ciph = Ciphersuite::new(pog, false);
        let srv = Server::setup(ciph);
        b.iter(|| server_eval(black_box(srv.clone()), black_box(&elems)))
    });
    c.bench_function("srv eval voprf ristretto n=5", |b| {
        let pog = PrimeOrderGroup::ristretto_255();
        let mut elems = Vec::new();
        for _ in 0..5 {
            elems.push((pog.clone().random_element)());
        }
        let ciph = Ciphersuite::new(pog, true);
        let srv = Server::setup(ciph);
        b.iter(|| server_eval(black_box(srv.clone()), black_box(&elems)))
    });
    c.bench_function("srv eval oprf p384 n=5", |b| {
        let pog = PrimeOrderGroup::p384();
        let mut elems = Vec::new();
        for _ in 0..5 {
            elems.push((pog.clone().random_element)());
        }
        let ciph = Ciphersuite::new(pog, false);
        let srv = Server::setup(ciph);
        b.iter(|| server_eval(black_box(srv.clone()), black_box(&elems)))
    });
    c.bench_function("srv eval voprf p384 n=5", |b| {
        let pog = PrimeOrderGroup::p384();
        let mut elems = Vec::new();
        for _ in 0..5 {
            elems.push((pog.clone().random_element)());
        }
        let ciph = Ciphersuite::new(pog, true);
        let srv = Server::setup(ciph);
        b.iter(|| server_eval(black_box(srv.clone()), black_box(&elems)))
    });

    // n=10
    c.bench_function("srv eval oprf ristretto n=10", |b| {
        let pog = PrimeOrderGroup::ristretto_255();
        let mut elems = Vec::new();
        for _ in 0..10 {
            elems.push((pog.clone().random_element)());
        }
        let ciph = Ciphersuite::new(pog, false);
        let srv = Server::setup(ciph);
        b.iter(|| server_eval(black_box(srv.clone()), black_box(&elems)))
    });
    c.bench_function("srv eval voprf ristretto n=10", |b| {
        let pog = PrimeOrderGroup::ristretto_255();
        let mut elems = Vec::new();
        for _ in 0..10 {
            elems.push((pog.clone().random_element)());
        }
        let ciph = Ciphersuite::new(pog, true);
        let srv = Server::setup(ciph);
        b.iter(|| server_eval(black_box(srv.clone()), black_box(&elems)))
    });
    c.bench_function("srv eval oprf p384 n=10", |b| {
        let pog = PrimeOrderGroup::p384();
        let mut elems = Vec::new();
        for _ in 0..10 {
            elems.push((pog.clone().random_element)());
        }
        let ciph = Ciphersuite::new(pog, false);
        let srv = Server::setup(ciph);
        b.iter(|| server_eval(black_box(srv.clone()), black_box(&elems)))
    });
    c.bench_function("srv eval voprf p384 n=10", |b| {
        let pog = PrimeOrderGroup::p384();
        let mut elems = Vec::new();
        for _ in 0..10 {
            elems.push((pog.clone().random_element)());
        }
        let ciph = Ciphersuite::new(pog, true);
        let srv = Server::setup(ciph);
        b.iter(|| server_eval(black_box(srv.clone()), black_box(&elems)))
    });

    // n=25
    c.bench_function("srv eval oprf ristretto n=25", |b| {
        let pog = PrimeOrderGroup::ristretto_255();
        let mut elems = Vec::new();
        for _ in 0..25 {
            elems.push((pog.clone().random_element)());
        }
        let ciph = Ciphersuite::new(pog, false);
        let srv = Server::setup(ciph);
        b.iter(|| server_eval(black_box(srv.clone()), black_box(&elems)))
    });
    c.bench_function("srv eval voprf ristretto n=25", |b| {
        let pog = PrimeOrderGroup::ristretto_255();
        let mut elems = Vec::new();
        for _ in 0..25 {
            elems.push((pog.clone().random_element)());
        }
        let ciph = Ciphersuite::new(pog, true);
        let srv = Server::setup(ciph);
        b.iter(|| server_eval(black_box(srv.clone()), black_box(&elems)))
    });
    c.bench_function("srv eval oprf p384 n=25", |b| {
        let pog = PrimeOrderGroup::p384();
        let mut elems = Vec::new();
        for _ in 0..25 {
            elems.push((pog.clone().random_element)());
        }
        let ciph = Ciphersuite::new(pog, false);
        let srv = Server::setup(ciph);
        b.iter(|| server_eval(black_box(srv.clone()), black_box(&elems)))
    });
    c.bench_function("srv eval voprf p384 n=25", |b| {
        let pog = PrimeOrderGroup::p384();
        let mut elems = Vec::new();
        for _ in 0..25 {
            elems.push((pog.clone().random_element)());
        }
        let ciph = Ciphersuite::new(pog, true);
        let srv = Server::setup(ciph);
        b.iter(|| server_eval(black_box(srv.clone()), black_box(&elems)))
    });

    // n=50
    c.bench_function("srv eval oprf ristretto n=50", |b| {
        let pog = PrimeOrderGroup::ristretto_255();
        let mut elems = Vec::new();
        for _ in 0..50 {
            elems.push((pog.clone().random_element)());
        }
        let ciph = Ciphersuite::new(pog, false);
        let srv = Server::setup(ciph);
        b.iter(|| server_eval(black_box(srv.clone()), black_box(&elems)))
    });
    c.bench_function("srv eval voprf ristretto n=50", |b| {
        let pog = PrimeOrderGroup::ristretto_255();
        let mut elems = Vec::new();
        for _ in 0..50 {
            elems.push((pog.clone().random_element)());
        }
        let ciph = Ciphersuite::new(pog, true);
        let srv = Server::setup(ciph);
        b.iter(|| server_eval(black_box(srv.clone()), black_box(&elems)))
    });
    c.bench_function("srv eval oprf p384 n=50", |b| {
        let pog = PrimeOrderGroup::p384();
        let mut elems = Vec::new();
        for _ in 0..50 {
            elems.push((pog.clone().random_element)());
        }
        let ciph = Ciphersuite::new(pog, false);
        let srv = Server::setup(ciph);
        b.iter(|| server_eval(black_box(srv.clone()), black_box(&elems)))
    });
    c.bench_function("srv eval voprf p384 n=50", |b| {
        let pog = PrimeOrderGroup::p384();
        let mut elems = Vec::new();
        for _ in 0..50 {
            elems.push((pog.clone().random_element)());
        }
        let ciph = Ciphersuite::new(pog, true);
        let srv = Server::setup(ciph);
        b.iter(|| server_eval(black_box(srv.clone()), black_box(&elems)))
    });

    // n=100
    c.bench_function("srv eval oprf ristretto n=100", |b| {
        let pog = PrimeOrderGroup::ristretto_255();
        let mut elems = Vec::new();
        for _ in 0..100 {
            elems.push((pog.clone().random_element)());
        }
        let ciph = Ciphersuite::new(pog, false);
        let srv = Server::setup(ciph);
        b.iter(|| server_eval(black_box(srv.clone()), black_box(&elems)))
    });
    c.bench_function("srv eval voprf ristretto n=100", |b| {
        let pog = PrimeOrderGroup::ristretto_255();
        let mut elems = Vec::new();
        for _ in 0..100 {
            elems.push((pog.clone().random_element)());
        }
        let ciph = Ciphersuite::new(pog, true);
        let srv = Server::setup(ciph);
        b.iter(|| server_eval(black_box(srv.clone()), black_box(&elems)))
    });
    c.bench_function("srv eval oprf p384 n=100", |b| {
        let pog = PrimeOrderGroup::p384();
        let mut elems = Vec::new();
        for _ in 0..100 {
            elems.push((pog.clone().random_element)());
        }
        let ciph = Ciphersuite::new(pog, false);
        let srv = Server::setup(ciph);
        b.iter(|| server_eval(black_box(srv.clone()), black_box(&elems)))
    });
    c.bench_function("srv eval voprf p384 n=100", |b| {
        let pog = PrimeOrderGroup::p384();
        let mut elems = Vec::new();
        for _ in 0..100 {
            elems.push((pog.clone().random_element)());
        }
        let ciph = Ciphersuite::new(pog, true);
        let srv = Server::setup(ciph);
        b.iter(|| server_eval(black_box(srv.clone()), black_box(&elems)))
    });

    /******************** CLIENT BENCHMARKS ********************/

    // setup
    c.bench_function("cli setup oprf ristretto", |b| b.iter(|| client_oprf_setup_ristretto()));
    c.bench_function("cli setup voprf ristretto", |b| b.iter(|| client_oprf_setup_p384()));
    c.bench_function("cli setup oprf p384", |b| b.iter(|| client_voprf_setup_ristretto(black_box("d8d3fd409a2a206295f5c8f840a12f0ce41aefe7d3b72b6246d72ee01649cf45".to_string()))));
    c.bench_function("cli setup voprf p384", |b| b.iter(|| client_voprf_setup_p384("030f290e5d9ec013f30968a4db66f36c20fd204a06bb8edf805a1936af744acde2f906f7190f2c206516fc49d23c65a424".to_string())));

    // blinding
    c.bench_function("client blind ristretto", |b| {
        let pog = PrimeOrderGroup::ristretto_255();
        let mut buf = Vec::new();
        (pog.clone().uniform_bytes)(&mut buf);
        let ciph = Ciphersuite::new(pog, false);
        let cli = Client::setup(ciph, None).unwrap();
        b.iter(|| client_blind(black_box(cli.clone()), black_box(buf.clone())))
    });
    c.bench_function("client blind p384", |b| {
        let pog = PrimeOrderGroup::p384();
        let mut buf = Vec::new();
        (pog.clone().uniform_bytes)(&mut buf);
        let ciph = Ciphersuite::new(pog, false);
        let cli = Client::setup(ciph, None).unwrap();
        b.iter(|| client_blind(black_box(cli.clone()), black_box(buf.clone())))
    });

    // unblinding
    // n=1
    c.bench_function("client unblind oprf ristretto n=1", |b| {
        let pog = PrimeOrderGroup::ristretto_255();
        let ciph = Ciphersuite::new(pog.clone(), false);
        let mut inputs = Vec::new();
        for _ in 0..1 {
            let mut buf = Vec::new();
            (pog.clone().uniform_bytes)(&mut buf);
            inputs.push(buf);
        }
        let (cli, blinded_inps, evals) = create_unblinding_values(ciph, &inputs);
        b.iter(|| client_unblind(black_box(cli.clone()), black_box(blinded_inps.clone()), black_box(evals.clone())))
    });
    c.bench_function("client unblind oprf p384 n=1", |b| {
        let pog = PrimeOrderGroup::p384();
        let ciph = Ciphersuite::new(pog.clone(), false);
        let mut inputs = Vec::new();
        for _ in 0..1 {
            let mut buf = Vec::new();
            (pog.clone().uniform_bytes)(&mut buf);
            inputs.push(buf);
        }
        let (cli, blinded_inps, evals) = create_unblinding_values(ciph, &inputs);
        b.iter(|| client_unblind(black_box(cli.clone()), black_box(blinded_inps.clone()), black_box(evals.clone())))
    });
    c.bench_function("client unblind voprf ristretto n=1", |b| {
        let pog = PrimeOrderGroup::ristretto_255();
        let ciph = Ciphersuite::new(pog.clone(), true);
        let mut inputs = Vec::new();
        for _ in 0..1 {
            let mut buf = Vec::new();
            (pog.clone().uniform_bytes)(&mut buf);
            inputs.push(buf);
        }
        let (cli, blinded_inps, evals) = create_unblinding_values(ciph, &inputs);
        b.iter(|| client_unblind(black_box(cli.clone()), black_box(blinded_inps.clone()), black_box(evals.clone())))
    });
    c.bench_function("client unblind voprf p384 n=1", |b| {
        let pog = PrimeOrderGroup::p384();
        let ciph = Ciphersuite::new(pog.clone(), true);
        let mut inputs = Vec::new();
        for _ in 0..1 {
            let mut buf = Vec::new();
            (pog.clone().uniform_bytes)(&mut buf);
            inputs.push(buf);
        }
        let (cli, blinded_inps, evals) = create_unblinding_values(ciph, &inputs);
        b.iter(|| client_unblind(black_box(cli.clone()), black_box(blinded_inps.clone()), black_box(evals.clone())))
    });

    // n=5
    c.bench_function("client unblind oprf ristretto n=5", |b| {
        let pog = PrimeOrderGroup::ristretto_255();
        let ciph = Ciphersuite::new(pog.clone(), false);
        let mut inputs = Vec::new();
        for _ in 0..5 {
            let mut buf = Vec::new();
            (pog.clone().uniform_bytes)(&mut buf);
            inputs.push(buf);
        }
        let (cli, blinded_inps, evals) = create_unblinding_values(ciph, &inputs);
        b.iter(|| client_unblind(black_box(cli.clone()), black_box(blinded_inps.clone()), black_box(evals.clone())))
    });
    c.bench_function("client unblind oprf p384 n=5", |b| {
        let pog = PrimeOrderGroup::p384();
        let ciph = Ciphersuite::new(pog.clone(), false);
        let mut inputs = Vec::new();
        for _ in 0..5 {
            let mut buf = Vec::new();
            (pog.clone().uniform_bytes)(&mut buf);
            inputs.push(buf);
        }
        let (cli, blinded_inps, evals) = create_unblinding_values(ciph, &inputs);
        b.iter(|| client_unblind(black_box(cli.clone()), black_box(blinded_inps.clone()), black_box(evals.clone())))
    });
    c.bench_function("client unblind voprf ristretto n=5", |b| {
        let pog = PrimeOrderGroup::ristretto_255();
        let ciph = Ciphersuite::new(pog.clone(), true);
        let mut inputs = Vec::new();
        for _ in 0..5 {
            let mut buf = Vec::new();
            (pog.clone().uniform_bytes)(&mut buf);
            inputs.push(buf);
        }
        let (cli, blinded_inps, evals) = create_unblinding_values(ciph, &inputs);
        b.iter(|| client_unblind(black_box(cli.clone()), black_box(blinded_inps.clone()), black_box(evals.clone())))
    });
    c.bench_function("client unblind voprf p384 n=5", |b| {
        let pog = PrimeOrderGroup::p384();
        let ciph = Ciphersuite::new(pog.clone(), true);
        let mut inputs = Vec::new();
        for _ in 0..5 {
            let mut buf = Vec::new();
            (pog.clone().uniform_bytes)(&mut buf);
            inputs.push(buf);
        }
        let (cli, blinded_inps, evals) = create_unblinding_values(ciph, &inputs);
        b.iter(|| client_unblind(black_box(cli.clone()), black_box(blinded_inps.clone()), black_box(evals.clone())))
    });

    // n=10
    c.bench_function("client unblind oprf ristretto n=10", |b| {
        let pog = PrimeOrderGroup::ristretto_255();
        let ciph = Ciphersuite::new(pog.clone(), false);
        let mut inputs = Vec::new();
        for _ in 0..10 {
            let mut buf = Vec::new();
            (pog.clone().uniform_bytes)(&mut buf);
            inputs.push(buf);
        }
        let (cli, blinded_inps, evals) = create_unblinding_values(ciph, &inputs);
        b.iter(|| client_unblind(black_box(cli.clone()), black_box(blinded_inps.clone()), black_box(evals.clone())))
    });
    c.bench_function("client unblind oprf p384 n=10", |b| {
        let pog = PrimeOrderGroup::p384();
        let ciph = Ciphersuite::new(pog.clone(), false);
        let mut inputs = Vec::new();
        for _ in 0..10 {
            let mut buf = Vec::new();
            (pog.clone().uniform_bytes)(&mut buf);
            inputs.push(buf);
        }
        let (cli, blinded_inps, evals) = create_unblinding_values(ciph, &inputs);
        b.iter(|| client_unblind(black_box(cli.clone()), black_box(blinded_inps.clone()), black_box(evals.clone())))
    });
    c.bench_function("client unblind voprf ristretto n=10", |b| {
        let pog = PrimeOrderGroup::ristretto_255();
        let ciph = Ciphersuite::new(pog.clone(), true);
        let mut inputs = Vec::new();
        for _ in 0..10 {
            let mut buf = Vec::new();
            (pog.clone().uniform_bytes)(&mut buf);
            inputs.push(buf);
        }
        let (cli, blinded_inps, evals) = create_unblinding_values(ciph, &inputs);
        b.iter(|| client_unblind(black_box(cli.clone()), black_box(blinded_inps.clone()), black_box(evals.clone())))
    });
    c.bench_function("client unblind voprf p384 n=10", |b| {
        let pog = PrimeOrderGroup::p384();
        let ciph = Ciphersuite::new(pog.clone(), true);
        let mut inputs = Vec::new();
        for _ in 0..10 {
            let mut buf = Vec::new();
            (pog.clone().uniform_bytes)(&mut buf);
            inputs.push(buf);
        }
        let (cli, blinded_inps, evals) = create_unblinding_values(ciph, &inputs);
        b.iter(|| client_unblind(black_box(cli.clone()), black_box(blinded_inps.clone()), black_box(evals.clone())))
    });

    // n=25
    c.bench_function("client unblind oprf ristretto n=25", |b| {
        let pog = PrimeOrderGroup::ristretto_255();
        let ciph = Ciphersuite::new(pog.clone(), false);
        let mut inputs = Vec::new();
        for _ in 0..25 {
            let mut buf = Vec::new();
            (pog.clone().uniform_bytes)(&mut buf);
            inputs.push(buf);
        }
        let (cli, blinded_inps, evals) = create_unblinding_values(ciph, &inputs);
        b.iter(|| client_unblind(black_box(cli.clone()), black_box(blinded_inps.clone()), black_box(evals.clone())))
    });
    c.bench_function("client unblind oprf p384 n=25", |b| {
        let pog = PrimeOrderGroup::p384();
        let ciph = Ciphersuite::new(pog.clone(), false);
        let mut inputs = Vec::new();
        for _ in 0..25 {
            let mut buf = Vec::new();
            (pog.clone().uniform_bytes)(&mut buf);
            inputs.push(buf);
        }
        let (cli, blinded_inps, evals) = create_unblinding_values(ciph, &inputs);
        b.iter(|| client_unblind(black_box(cli.clone()), black_box(blinded_inps.clone()), black_box(evals.clone())))
    });
    c.bench_function("client unblind voprf ristretto n=25", |b| {
        let pog = PrimeOrderGroup::ristretto_255();
        let ciph = Ciphersuite::new(pog.clone(), true);
        let mut inputs = Vec::new();
        for _ in 0..25 {
            let mut buf = Vec::new();
            (pog.clone().uniform_bytes)(&mut buf);
            inputs.push(buf);
        }
        let (cli, blinded_inps, evals) = create_unblinding_values(ciph, &inputs);
        b.iter(|| client_unblind(black_box(cli.clone()), black_box(blinded_inps.clone()), black_box(evals.clone())))
    });
    c.bench_function("client unblind voprf p384 n=25", |b| {
        let pog = PrimeOrderGroup::p384();
        let ciph = Ciphersuite::new(pog.clone(), true);
        let mut inputs = Vec::new();
        for _ in 0..25 {
            let mut buf = Vec::new();
            (pog.clone().uniform_bytes)(&mut buf);
            inputs.push(buf);
        }
        let (cli, blinded_inps, evals) = create_unblinding_values(ciph, &inputs);
        b.iter(|| client_unblind(black_box(cli.clone()), black_box(blinded_inps.clone()), black_box(evals.clone())))
    });

    // n=50
    c.bench_function("client unblind oprf ristretto n=50", |b| {
        let pog = PrimeOrderGroup::ristretto_255();
        let ciph = Ciphersuite::new(pog.clone(), false);
        let mut inputs = Vec::new();
        for _ in 0..50 {
            let mut buf = Vec::new();
            (pog.clone().uniform_bytes)(&mut buf);
            inputs.push(buf);
        }
        let (cli, blinded_inps, evals) = create_unblinding_values(ciph, &inputs);
        b.iter(|| client_unblind(black_box(cli.clone()), black_box(blinded_inps.clone()), black_box(evals.clone())))
    });
    c.bench_function("client unblind oprf p384 n=50", |b| {
        let pog = PrimeOrderGroup::p384();
        let ciph = Ciphersuite::new(pog.clone(), false);
        let mut inputs = Vec::new();
        for _ in 0..50 {
            let mut buf = Vec::new();
            (pog.clone().uniform_bytes)(&mut buf);
            inputs.push(buf);
        }
        let (cli, blinded_inps, evals) = create_unblinding_values(ciph, &inputs);
        b.iter(|| client_unblind(black_box(cli.clone()), black_box(blinded_inps.clone()), black_box(evals.clone())))
    });
    c.bench_function("client unblind voprf ristretto n=50", |b| {
        let pog = PrimeOrderGroup::ristretto_255();
        let ciph = Ciphersuite::new(pog.clone(), true);
        let mut inputs = Vec::new();
        for _ in 0..50 {
            let mut buf = Vec::new();
            (pog.clone().uniform_bytes)(&mut buf);
            inputs.push(buf);
        }
        let (cli, blinded_inps, evals) = create_unblinding_values(ciph, &inputs);
        b.iter(|| client_unblind(black_box(cli.clone()), black_box(blinded_inps.clone()), black_box(evals.clone())))
    });
    c.bench_function("client unblind voprf p384 n=50", |b| {
        let pog = PrimeOrderGroup::p384();
        let ciph = Ciphersuite::new(pog.clone(), true);
        let mut inputs = Vec::new();
        for _ in 0..50 {
            let mut buf = Vec::new();
            (pog.clone().uniform_bytes)(&mut buf);
            inputs.push(buf);
        }
        let (cli, blinded_inps, evals) = create_unblinding_values(ciph, &inputs);
        b.iter(|| client_unblind(black_box(cli.clone()), black_box(blinded_inps.clone()), black_box(evals.clone())))
    });

    // n=100
    c.bench_function("client unblind oprf ristretto n=100", |b| {
        let pog = PrimeOrderGroup::ristretto_255();
        let ciph = Ciphersuite::new(pog.clone(), false);
        let mut inputs = Vec::new();
        for _ in 0..100 {
            let mut buf = Vec::new();
            (pog.clone().uniform_bytes)(&mut buf);
            inputs.push(buf);
        }
        let (cli, blinded_inps, evals) = create_unblinding_values(ciph, &inputs);
        b.iter(|| client_unblind(black_box(cli.clone()), black_box(blinded_inps.clone()), black_box(evals.clone())))
    });
    c.bench_function("client unblind oprf p384 n=100", |b| {
        let pog = PrimeOrderGroup::p384();
        let ciph = Ciphersuite::new(pog.clone(), false);
        let mut inputs = Vec::new();
        for _ in 0..100 {
            let mut buf = Vec::new();
            (pog.clone().uniform_bytes)(&mut buf);
            inputs.push(buf);
        }
        let (cli, blinded_inps, evals) = create_unblinding_values(ciph, &inputs);
        b.iter(|| client_unblind(black_box(cli.clone()), black_box(blinded_inps.clone()), black_box(evals.clone())))
    });
    c.bench_function("client unblind voprf ristretto n=100", |b| {
        let pog = PrimeOrderGroup::ristretto_255();
        let ciph = Ciphersuite::new(pog.clone(), true);
        let mut inputs = Vec::new();
        for _ in 0..100 {
            let mut buf = Vec::new();
            (pog.clone().uniform_bytes)(&mut buf);
            inputs.push(buf);
        }
        let (cli, blinded_inps, evals) = create_unblinding_values(ciph, &inputs);
        b.iter(|| client_unblind(black_box(cli.clone()), black_box(blinded_inps.clone()), black_box(evals.clone())))
    });
    c.bench_function("client unblind voprf p384 n=100", |b| {
        let pog = PrimeOrderGroup::p384();
        let ciph = Ciphersuite::new(pog.clone(), true);
        let mut inputs = Vec::new();
        for _ in 0..100 {
            let mut buf = Vec::new();
            (pog.clone().uniform_bytes)(&mut buf);
            inputs.push(buf);
        }
        let (cli, blinded_inps, evals) = create_unblinding_values(ciph, &inputs);
        b.iter(|| client_unblind(black_box(cli.clone()), black_box(blinded_inps.clone()), black_box(evals.clone())))
    });

    // finalize
    c.bench_function("client finalize ristretto", |b| {
        let pog = PrimeOrderGroup::ristretto_255();
        let ciph = Ciphersuite::new(pog.clone(), false);
        let mut inputs = Vec::new();
        for _ in 0..1 {
            let mut buf = Vec::new();
            (pog.clone().uniform_bytes)(&mut buf);
            inputs.push(buf);
        }
        let (cli, blinded_inps, evals) = create_unblinding_values(ciph, &inputs);
        let unblinded = client_unblind(black_box(cli.clone()), black_box(blinded_inps.clone()), black_box(evals.clone()));
        b.iter(|| client_finalize(black_box(cli.clone()), black_box(&inputs[0]), black_box(&unblinded[0]), black_box("some_aux_data".as_bytes())))
    });
    c.bench_function("client finalize p384", |b| {
        let pog = PrimeOrderGroup::p384();
        let ciph = Ciphersuite::new(pog.clone(), false);
        let mut inputs = Vec::new();
        for _ in 0..1 {
            let mut buf = Vec::new();
            (pog.clone().uniform_bytes)(&mut buf);
            inputs.push(buf);
        }
        let (cli, blinded_inps, evals) = create_unblinding_values(ciph, &inputs);
        let unblinded = client_unblind(black_box(cli.clone()), black_box(blinded_inps.clone()), black_box(evals.clone()));
        b.iter(|| client_finalize(black_box(cli.clone()), black_box(&inputs[0]), black_box(&unblinded[0]), black_box("some_aux_data".as_bytes())))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
