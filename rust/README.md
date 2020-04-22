# voprf-rs

A [rust](https://www.rust-lang.org/) implementation of the VOPRF protocol in
[draft-irtf-cfrg-voprf](https://datatracker.ietf.org/doc/draft-irtf-cfrg-voprf/).

- [voprf-rs](#voprf-rs)
  - [Build](#build)
  - [Documentation](#documentation)
  - [Testing & benchmarks](#testing--benchmarks)
  - [Server](#server)
  - [Client](#client)
  - [Generate test vectors](#generate-test-vectors)
  - [Supported ciphersuites](#supported-ciphersuites)

## Build

Run:

```
make build
```

## Documentation

Run:

```
make docs
```

Running this command should open a new browser window with the
documentation page.

## Testing & benchmarks

Run tests:

```
make test
```

Run benchmarks:

```
make bench
```

## Server

Starts a server for running the (V)OPRF protocol. See ["Supported
ciphersuites"](#supported-ciphersuites) for supported values of `<group_name>`.

- Run server (OPRF):

    ```
    make server GROUP=<group>
    ```

    - Expected output:

        ```
        RUST_BACKTRACE=1 cargo build
        Finished dev [unoptimized + debuginfo] target(s) in 0.15s
        RUST_BACKTRACE=1 ./target/debug/main --group=<group> --mode=server --max_evals=10
        Server listening at 127.0.0.1:3001 and running with ciphersuite OPRF-<group>-HKDF-SHA512-<h2c>
        ```

- Run server (VOPRF):

    ```
    make server GROUP=<group> VERIFIABLE=1
    ```

    - Expected output:

        ```
        RUST_BACKTRACE=1 cargo build
        Finished dev [unoptimized + debuginfo] target(s) in 0.59s
        RUST_BACKTRACE=1 ./target/debug/main --group=<group> --mode=server --verifiable=true --test=0
        ***** Testing mode activated *****
        Secret key: <secret-key>
        Server listening at 127.0.0.1:3001 and running with ciphersuite VOPRF-<group>-HKDF-SHA512-<h2c>
        Public key: <public-key>
        ```

- We support `<group> in [P384, P521, curve448, ristretto255]`

## Client

Starts a client that communicates with a running (V)OPRF server (default port 3001).

- Run client (OPRF):

    ```
    make client GROUP=<group>
    ```

  - Expected output (OPRF):

      ```
      RUST_BACKTRACE=1 cargo build
      Finished dev [unoptimized + debuginfo] target(s) in 0.16s
      RUST_BACKTRACE=1 ./target/debug/main --group=P384 --mode=client --n=3
      Client attempting to connect to http://127.0.0.1:3001 and running with ciphersuite OPRF-P384-HKDF-SHA512-SSWU-RO
      ***********
      Inputs
      ===========
      ...
      ***********
      ***********
      Blinds
      ===========
      ...
      ***********
      ***********
      Outputs
      ===========
      ...
      ***********
      ***********
      Evaluated elements
      ===========
      ...
      ***********
      ***********
      Proof values
      ===========

      ***********
      ```

- Run client (VOPRF):

    ```
    cargo run -- --group=<group_name> --mode=client --verifiable --pk=<public_key>
    ```

  - Expected output (VOPRF):

      ```
      RUST_BACKTRACE=1 cargo build
      Finished dev [unoptimized + debuginfo] target(s) in 0.16s
      RUST_BACKTRACE=1 ./target/debug/main --group=<group> --mode=client --n=3 --verifiable=true --pk=<public_key>
      Public key: <public_key>
      Client attempting to connect to http://127.0.0.1:3001 and running with ciphersuite VOPRF-<group>-HKDF-SHA512-<h2c>
      ***********
      Inputs
      ===========
      ...
      ***********
      ***********
      Blinds
      ===========
      ...
      ***********
      ***********
      Outputs
      ===========
      ...
      ***********
      ***********
      Evaluated elements
      ===========
      ...
      ***********
      ***********
      Proof values
      ===========
      ...
      ***********
      ```

## Generate test vectors

Run the server & client above, with an additional flag `TEST=<value>`
where `<value>` corresponds to the index of the test vector that is
required. Valid test vectors currently take indices between `0` and `8`.

## Supported ciphersuites

- OPRF-P384-HKDF-SHA512-SSWU-RO, `<group_name> = P384`
- VOPRF-P384-HKDF-SHA512-SSWU-RO, `<group_name> = P384`
- OPRF-P521-HKDF-SHA512-SSWU-RO, `<group_name> = P521`
- VOPRF-P521-HKDF-SHA512-SSWU-RO, `<group_name> = P521`
- OPRF-curve448-HKDF-SHA512-ELL2-RO, `<group_name> = curve448`
- VOPRF-curve448-HKDF-SHA512-ELL2-RO, `<group_name> = curve448`
- OPRF-ristretto255-HKDF-SHA512-ELL2-RO `<group_name> = ristretto255` (EXPERIMENTAL)
- VOPRF-ristretto255-HKDF-SHA512-ELL2-RO `<group_name> = ristretto255` (EXPERIMENTAL)