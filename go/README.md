# voprf-poc-js

A [golang](https://golang.org/) implementation of the VOPRF in
[draft-irtf-cfrg-voprf](https://datatracker.ietf.org/doc/draft-irtf-cfrg-voprf/).

## Quickstart

### Server

Starts a server for running the (V)OPRF protocol.

Run server (OPRF):

```
make server
```

Run server (VOPRF):

```
make server VERIFIABLE=true
```

Expected output:

```
go run main.go --mode=server --max_evals=10 --ciph=<ciphersuite>
Starting server...
Server listening on port 3001
Public key: <public-key>
```

### Client

Starts a client that communicates with a running (V)OPRF server (default port 3001).

- Run client (OPRF):

    ```
    make client
    ```

  - Expected output (OPRF):

      ```
      go run main.go --mode=client --n=3 --ciph=<ciphersuite>
      Starting client...
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
      Evaluations
      ===========
      {
      "elements": [
          ...
      ]
      }
      ***********
      ```

- Run client (VOPRF):

    ```
    make server VERIFIABLE=true PUBLIC_KEY=<server_public_key>
    ```

  - Expected output (VOPRF):

        ```
        go run main.go --mode=client --n=3 --ciph=<ciphersuite> --pk=<server_public_key>
        Starting client...
        Setting public key:  <server_public_key>
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
        Evaluations
        ===========
        {
        "elements": [
            ...
        ],
        "proof": [
            ...
        ]
        }
        ***********
        ```

The chosen curve in the ciphersuite can be changed by appending
`CURVE=<chosen_curve>` to the make command. Only `P384` and `P521` are currently
supported.

### Generate test vectors

To generate test vectors for the (V)OPRF, run a server with `max_evals >= 6` (it
is set to `10` by default) and then run:

```
make test-vectors
```

As before, we can set `VERIFIABLE`, `PUBLIC_KEY` and `CURVE` to alter the
ciphersuite.