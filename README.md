# voprf-poc

A selection of proof-of-concept implementations of the OPRF protocol
detailed in <https://datatracker.ietf.org/doc/draft-irtf-cfrg-voprf/>.

![](https://github.com/alxdavids/voprf-poc/workflows/Tests%20on%20CI/badge.svg)

## Disclaimer

**The implementations in this repository have not had been reviewed from
a security perspective. They are NOT suitable to be used for
anything other than experimental purposes. The implementations are a
WIP and subsequently do not implement all drafted functionality yet.**

## Quickstart

Clone:
```
git clone git@github.com:alxdavids/voprf-poc.git --recursive
```

## Implementations

We support some subset of the available VOPRF functionality in the
following languages:

- [go](go/): A golang v1.12 implementation
- [rust](rust/): A rust 1.40.0 implementation based on the 
  [redox-ecc](https://github.com/armfazh/redox-ecc/) crate.

All available VOPRF implementations provide interoperable HTTP server &
client binaries that can be used to perform the (V)OPRF protocol in the
latest version of the draft. See the README.md files in the subfolders
for specific instructions on how to run these.

## Supported ciphersuites

### Official

The state of support for the officially documented ciphersuites in
<https://datatracker.ietf.org/doc/draft-irtf-cfrg-voprf/>.

| Ciphersuite | go | rust |
| ----------- | -- | ---- |
| OPRF-curve448-HKDF-SHA512-ELL2-RO | Y | Y |
| OPRF-P384-HKDF-SHA512-SSWU-RO | Y | Y |
| OPRF-P521-HKDF-SHA512-SSWU-RO | Y | Y |
| VOPRF-curve448-HKDF-SHA512-ELL2-RO | Y | Y |
| VOPRF-P384-HKDF-SHA512-SSWU-RO | Y | Y |
| VOPRF-P521-HKDF-SHA512-SSWU-RO | Y | Y |

### Experimental

Support for experimental ciphersuites that are not part of the draft
specification.

| Ciphersuite | go | rust |
| ----------- | -- | ---- |
| OPRF-ristretto255-HKDF-SHA512-ELL2-RO | N | Y |
| VOPRF-ristretto255-HKDF-SHA512-ELL2-RO | N | Y |
