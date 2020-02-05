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
cargo build
```

## Documentation

Run:

```
cargo doc --lib --open
```

and navigate to http://localhost:6060/pkg.

## Testing & benchmarks

Run tests:

```
cargo test
```

Run benchmarks:

```
cargo bench
```

## Server

Starts a server for running the (V)OPRF protocol. See ["Supported
ciphersuites"](#supported-ciphersuites) for supported values of `<group_name>`.

- Run server (OPRF):

    ```
    cargo run -- --group=<group_name> --mode=server
    ```

- Run server (VOPRF):

    ```
    cargo run -- --group=<group_name> --mode=server --verifiable
    ```

    - Expected output:

        ```
        cargo run -- --group=P384 --mode=server --verifiable
        Server listening at 127.0.0.1:3001 and running with ciphersuite VOPRF-P384-HKDF-SHA512-SSWU-RO
        Public key: <public-key>
        ```

## Client

Starts a client that communicates with a running (V)OPRF server (default port 3001).

- Run client (OPRF):

    ```
    cargo run -- --group=<group_name> --mode=client
    ```

  - Expected output (OPRF):

      ```
      cargo run -- --group=P384 --mode=client
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
      cargo run -- --group=P384 --mode=client --verifiable --pk=<public_key>
      Public key: <public_key>
      Client attempting to connect to http://127.0.0.1:3001 and running with ciphersuite VOPRF-P384-HKDF-SHA512-SSWU-RO
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

Run the server & client above, with an additional flag `--test=<value>` where
`<value>` corresponds to the index of the test vector that is required. Valid
test vectors currently take indices between `0` and `8`.

## Supported ciphersuites

- OPRF-P384-HKDF-SHA512-SSWU-RO, `<group_name> = P384`
- VOPRF-P384-HKDF-SHA512-SSWU-RO, `<group_name> = P384`
- OPRF-ristretto255-HKDF-SHA512-SSWU-RO `<group_name> = ristretto255` (EXPERIMENTAL)
- VOPRF-ristretto255-HKDF-SHA512-SSWU-RO `<group_name> = ristretto255` (EXPERIMENTAL)
