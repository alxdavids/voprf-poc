# voprf-poc

A selection of proof-of-concept implementations of the OPRF protocol detailed
in <https://datatracker.ietf.org/doc/draft-irtf-cfrg-voprf/>.

## Quickstart

Clone:
```
go clone git@github.com:alxdavids/voprf-poc.git --recursive
```

## Implementations

We support some subset of the available VOPRF functionality in the following
languages:

- [go](go/): A golang v1.12 implementation
- [rust](rust/): A rust 1.40.0 implementation based on a fork of
  [*ring*](https://github.com/alxdavids/ring-ecc/) for performing ECC
  operations.

All available VOPRF implementations provide interoperable HTTP server & client
binaries that can be used to perform the (V)OPRF protocol in the latest version
of the draft. See the README.md files in the subfolders for specific
instructions on how to run these.

## Supported ciphersuites

### Official

The state of support for the officially documented ciphersuites in
<https://datatracker.ietf.org/doc/draft-irtf-cfrg-voprf/>.

| Ciphersuite | go | rust |
| ----------- | -- | ---- |
| OPRF-curve448-HKDF-SHA512-ELL2-RO | N (#9) | N |
| OPRF-P384-HKDF-SHA512-SSWU-RO | Y | Y |
| OPRF-P521-HKDF-SHA512-SSWU-RO | Y | N |
| VOPRF-curve448-HKDF-SHA512-ELL2-RO | N (#9) | N |
| VOPRF-P384-HKDF-SHA512-SSWU-RO | Y | Y |
| VOPRF-P521-HKDF-SHA512-SSWU-RO | Y | N |

### Experimental

Support for experimental ciphersuites that are not part of the draft
specification.

| Ciphersuite | go | rust |
| ----------- | -- | ---- |
| OPRF-ristretto255-HKDF-SHA512-ELL2-RO | N | Y |
| VOPRF-ristretto255-HKDF-SHA512-ELL2-RO | N | Y |