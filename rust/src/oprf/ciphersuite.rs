//! The ciphersuite module describes the `Ciphersuite` struct. This struct, in
//! turn, provides the functionality that is implemented by any of the supported
//! (V)OPRF settings detailed in draft-irtf-cfrg-voprf. In particular, it
//! provides access to the underlying prime-order group instantiation, along
//! with the functions `H1, ..., H5` required in the specification. See
//! https://tools.ietf.org/html/draft-irtf-cfrg-voprf-02#section-6 for a full
//! list of supported ciphersuites in the spec.

use hmac::{Hmac,Mac};
use digest::Digest;

// supported primitives
use sha2::Sha512;
use super::groups::PrimeOrderGroup;
use curve25519_dalek::ristretto::RistrettoPoint;
use super::groups::p384::NistPoint;
use super::groups::p384_redox::RedoxPoint;
use hkdf_sha512::Hkdf;
use super::super::utils::copy_into;

use std::io::Error;
use super::super::errors::err_finalization;

/// The Supported trait defines the `PrimeOrderGroup<T,H>` instantiations that
/// are currently supported by the VOPRF implementation. Currently, only
/// `T=curve25519_dalek::ristretto::RistrettoPoint` and `H=sha2::Sha512` are
/// supported. This corresponds to an experimental ristretto255 ciphersuite that
/// is not defined in draft-irth-cfrg-voprf-02.
pub trait Supported {
    /// Returns the string identifier for the supported group
    fn name(&self) -> String;
}

impl Supported for PrimeOrderGroup<RistrettoPoint,Sha512> {
    fn name(&self) -> String {
        String::from("ristretto255-HKDF-SHA512-ELL2-RO")
    }
}

impl Supported for PrimeOrderGroup<NistPoint,Sha512> {
    fn name(&self) -> String {
        String::from("P384-HKDF-SHA512-SSWU-RO")
    }
}

impl Supported for PrimeOrderGroup<RedoxPoint,Sha512> {
    fn name(&self) -> String {
        String::from("P384_redox-HKDF-SHA512-SSWU-RO")
    }
}

// Returns the name of the primitive set if it is supported
fn get_name<S: Supported>(x: &S) -> String {
    x.name()
}

/// The Ciphersuite struct gives access to the core functionality provided by a
/// VOPRF ciphersuite (see:
/// <https://tools.ietf.org/html/draft-irtf-cfrg-voprf-02#section-6>). In
/// essence, this is the PrimeOrderGroup instantiation that is used, along with
/// ancillary functions for hashing and manipulating data associated the group
/// that is used. If the parameter `verifiable` is true, then the ciphersuite
/// corresponds to a VOPRF instance, and otherwise merely an OPRF.
///
/// # Example
///
/// ```
/// use voprf_rs::oprf::groups::PrimeOrderGroup;
/// use voprf_rs::oprf::ciphersuite::Ciphersuite;
///
/// // create instance of Ciphersuite
/// let pog  = PrimeOrderGroup::ristretto_255();
/// let ciph = Ciphersuite::new(pog.clone(), false);
///
/// // encode bytes to group element
/// let _ = ciph.h1(b"some_input");
///
/// // compute HMAC value
/// let mut key: Vec<u8> = Vec::new();
/// (pog.uniform_bytes)(&mut key);
/// let _ = match ciph.h2(&key) {
///     Ok(o) => o,
///     Err(e) => panic!(e)
/// };
///
/// // compute h3() and h4() hash outputs
/// let mut out_3: Vec<u8> = Vec::new();
/// let mut out_4: Vec<u8> = Vec::new();
/// let _ = ciph.h3(b"h3_input_bytes", &mut out_3);
/// let _ = ciph.h4(b"h4_input_bytes", &mut out_4);
///
/// // get access to HKDF instance as specified in utils::hkdf::Hkdf;
/// let hkdf = ciph.h5();
/// ```
#[derive(Clone)]
pub struct Ciphersuite<T,H>
        where PrimeOrderGroup<T,H>: Clone {
    /// name of the ciphersuite
    pub name: String,
    /// A boolean indiciating whether the ciphersuite corresponds to a VOPRF or
    /// not (OPRF only).
    pub verifiable: bool,
    /// The PrimeOrderGroup instantiation that the ciphersuite corresponds to
    pub pog: PrimeOrderGroup<T,H>
}

impl<T,H> Ciphersuite<T,H>
        where PrimeOrderGroup<T,H>: Supported, T: Clone, H: Default
        + digest::Input + digest::BlockInput + digest::FixedOutput
        + digest::Reset + Clone {

    /// Constructor for the Ciphersuite object
    ///
    /// # Arguments
    ///
    /// * `pog`: An instance of a PrimeOrderGroup object, such as
    ///   `voprf_rs::oprf::groups::PrimeOrderGroup::ristretto255`.
    /// * `verifiable`: A bool parameter indicating whether the ciphersuite
    ///   corresponds to a VOPRF instantiation, or not.
    pub fn new(pog: PrimeOrderGroup<T,H>, verifiable: bool) -> Ciphersuite<T,H> {
        let mut name = String::from("");
        match verifiable {
            true => name.push_str("VOPRF-"),
            false => name.push_str("OPRF-"),
        }
        name.push_str(&get_name(&pog));
        Ciphersuite {
            name: name,
            verifiable: verifiable,
            pog: pog
        }
    }

    /// Provides access to the mechanism for deterministically mapping a
    /// sequence of bytes to an element of the group. This process should not
    /// reveal the discrete logarithm of the group element with respect to the
    /// fixed generator of the underlying group.
    ///
    /// # Arguments
    ///
    /// * `buf`: the sequence of bytes to encode as a curve point
    pub fn h1(&self, buf: &[u8]) -> T {
        (self.pog.encode_to_group)(buf)
    }

    /// Provides access to the HMAC algorithm that is used in running
    /// [OPRF_Finalize](https://tools.ietf.org/html/draft-irtf-cfrg-voprf-02#section-4.5.5)
    /// and
    /// [VOPRF_Finalize](https://tools.ietf.org/html/draft-irtf-cfrg-voprf-02#section-4.6.5).
    ///
    ///
    /// # Arguments
    ///
    /// * `key`: the sequence of bytes that is used as the HMAC key
    pub fn h2(&self, key: &[u8]) -> Result<Hmac<H>, Error> {
        match Hmac::<H>::new_varkey(key) {
            Ok(mac) => {
                return Ok(mac);
            },
            Err(_) => return Err(err_finalization())
        }
    }

    /// a private function used for evaluating the hash function associated the
    /// PrimeOrderGroup object.
    fn hash_generic(&self, inp: &[u8], out: &mut Vec<u8>) {
        let mut hash_fn = (self.pog.hash)();
        hash_fn.input(inp);
        let res = hash_fn.result().to_vec();
        copy_into(&res, out);
    }

    /// Provides access to the hash function associated with the PrimeOrderGroup
    /// and moves the output bytes into the provided buffer. Used in DLEQ proof
    /// generation/verification.
    ///
    /// # Arguments
    ///
    /// * `inp`: the sequence of bytes that is input to the hash algorithm
    /// * `out`: the output bytes
    pub fn h3(&self, inp: &[u8], out: &mut Vec<u8>) {
        self.hash_generic(inp, out)
    }

    /// same as h3, used in batched DLEQ proof generation/verification
    pub fn h4(&self, inp: &[u8], out: &mut Vec<u8>) {
        self.hash_generic(inp, out)
    }

    /// Returns an instance of the HKDF primitive specified in
    /// https://tools.ietf.org/html/draft-irtf-cfrg-voprf-02#section-6.
    pub fn h5(&self) -> Hkdf {
        Hkdf{}
    }
}

#[cfg(test)]
mod tests {
    use super::{PrimeOrderGroup,Ciphersuite};

    #[test]
    fn ristretto_oprf_ciphersuite() {
        let ciph = Ciphersuite::new(PrimeOrderGroup::ristretto_255(), false);
        assert_eq!(ciph.name, String::from("OPRF-ristretto255-HKDF-SHA512-ELL2-RO"));
        assert_eq!(ciph.verifiable, false);
    }

    #[test]
    fn ristretto_voprf_ciphersuite() {
        let ciph = Ciphersuite::new(PrimeOrderGroup::ristretto_255(), true);
        assert_eq!(ciph.name, String::from("VOPRF-ristretto255-HKDF-SHA512-ELL2-RO"));
        assert_eq!(ciph.verifiable, true);
    }

    #[test]
    fn ristretto_h1() {
        let pog = PrimeOrderGroup::ristretto_255();
        let ciph = Ciphersuite::new(pog.clone(), true);
        let ge = ciph.h1(&[0; 32]);
        assert_eq!((pog.is_valid)(&ge), true);
    }

    #[test]
    fn ristretto_h3_h4() {
        let ciph = Ciphersuite::new(PrimeOrderGroup::ristretto_255(), true);
        let mut h3_res: Vec<u8> = Vec::new();
        let mut h4_res: Vec<u8> = Vec::new();
        ciph.h3(&[0; 32], &mut h3_res);
        ciph.h4(&[0; 32], &mut h4_res);
        // should be equal as both functions use the same hash
        assert_eq!(h3_res, h4_res);
    }

    #[test]
    fn p384_oprf_ciphersuite() {
        let ciph = Ciphersuite::new(PrimeOrderGroup::p384(), false);
        assert_eq!(ciph.name, String::from("OPRF-P384-HKDF-SHA512-SSWU-RO"));
        assert_eq!(ciph.verifiable, false);
    }

    #[test]
    fn p384_voprf_ciphersuite() {
        let ciph = Ciphersuite::new(PrimeOrderGroup::p384(), true);
        assert_eq!(ciph.name, String::from("VOPRF-P384-HKDF-SHA512-SSWU-RO"));
        assert_eq!(ciph.verifiable, true);
    }

    #[test]
    fn p384_h1() {
        let pog = PrimeOrderGroup::p384();
        let ciph = Ciphersuite::new(pog.clone(), true);
        let ge = ciph.h1(&[0; 32]);
        assert_eq!((pog.is_valid)(&ge), true);
    }

    #[test]
    fn p384_h3_h4() {
        let ciph = Ciphersuite::new(PrimeOrderGroup::p384(), true);
        let mut h3_res: Vec<u8> = Vec::new();
        let mut h4_res: Vec<u8> = Vec::new();
        ciph.h3(&[0; 32], &mut h3_res);
        ciph.h4(&[0; 32], &mut h4_res);
        // should be equal as both functions use the same hash
        assert_eq!(h3_res, h4_res);
    }

    #[test]
    fn p384_redox_oprf_ciphersuite() {
        let ciph = Ciphersuite::new(PrimeOrderGroup::p384_redox(), false);
        assert_eq!(ciph.name, String::from("OPRF-P384_redox-HKDF-SHA512-SSWU-RO"));
        assert_eq!(ciph.verifiable, false);
    }

    #[test]
    fn p384_redox_voprf_ciphersuite() {
        let ciph = Ciphersuite::new(PrimeOrderGroup::p384_redox(), true);
        assert_eq!(ciph.name, String::from("VOPRF-P384_redox-HKDF-SHA512-SSWU-RO"));
        assert_eq!(ciph.verifiable, true);
    }

    #[test]
    fn p384_redox_h1() {
        let pog = PrimeOrderGroup::p384_redox();
        let ciph = Ciphersuite::new(pog.clone(), true);
        let ge = ciph.h1(&[0; 32]);
        assert_eq!((pog.is_valid)(&ge), true);
    }

    #[test]
    fn p384_redox_h3_h4() {
        let ciph = Ciphersuite::new(PrimeOrderGroup::p384_redox(), true);
        let mut h3_res: Vec<u8> = Vec::new();
        let mut h4_res: Vec<u8> = Vec::new();
        ciph.h3(&[0; 32], &mut h3_res);
        ciph.h4(&[0; 32], &mut h4_res);
        // should be equal as both functions use the same hash
        assert_eq!(h3_res, h4_res);
    }

    // TODO: test vectors for HMAC and HKDF?
}