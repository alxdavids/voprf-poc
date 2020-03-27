//! The `ristretto` module allows creating a `PrimeOrederGroup` object for
//! performing (V)OPRF operations in the group associated with
//! [ristretto255](https://tools.ietf.org/html/draft-hdevalence-cfrg-ristretto-01).
//!
//! # Example
//!
//! ```
//! use voprf_rs::oprf::groups::PrimeOrderGroup;
//! let pog = PrimeOrderGroup::ristretto_255();
//! ```

use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;

use super::{PrimeOrderGroup,GroupID};
use super::super::super::utils::{rand_bytes,copy_into};
use hkdf_sha512::Hkdf;
use super::super::super::errors::err_deserialization;

use sha2::Sha512;
use sha2::Digest;
use rand_core::OsRng;
use byteorder::{LittleEndian, WriteBytesExt};

const RISTRETTO_BYTE_LENGTH: usize = 32;

/// WARNING: The ristretto255 group is not officially supported in
/// draft-irtf-cfrg-voprf-02. This instantiation is only intended as an
/// experiment.
///
/// Constructs an instance of `PrimeOrderGroup` using the implied group
/// constructed around the implementation of the ristretto255 prime-order group
/// (https://tools.ietf.org/html/draft-hdevalence-cfrg-ristretto-01) found in
/// curve25519_dalek (https://doc.dalek.rs/curve25519_dalek/ristretto). Group
/// operations involving scalars are use the `curve25519_dalek::scalar::Scalar`
/// struct provided by the same crate.
impl PrimeOrderGroup<RistrettoPoint,Sha512> {
    /// Returns an instance of PrimeOrderGroup that allows performing (V)OPRF
    /// operations using the ristretto255 group.
    ///
    /// # Example
    ///
    /// ```
    /// use voprf_rs::oprf::groups::PrimeOrderGroup;
    /// let pog = PrimeOrderGroup::ristretto_255();
    /// ```
    pub fn ristretto_255() -> PrimeOrderGroup<RistrettoPoint,Sha512> {
        PrimeOrderGroup{
            group_id: GroupID::Ristretto255,
            generator: RISTRETTO_BASEPOINT_POINT,
            byte_length: RISTRETTO_BYTE_LENGTH,
            hash: || ristretto_hash(),
            deserialize: |buf: &[u8]| {
                let mut compressed = CompressedRistretto([0u8; RISTRETTO_BYTE_LENGTH]);
                compressed.0.copy_from_slice(&buf[..RISTRETTO_BYTE_LENGTH]);
                match compressed.decompress() {
                    Some(rp) => return Ok(rp),
                    None => return Err(err_deserialization())
                }
            },
            encode_to_group: |buf: &[u8]| {
                RistrettoPoint::hash_from_bytes::<Sha512>(buf)
            },
            is_valid: |_: &RistrettoPoint| true,
            is_equal: |p1: &RistrettoPoint, p2: &RistrettoPoint| p1 == p2,
            add: |p1: &RistrettoPoint, p2: &RistrettoPoint| p1 + p2,
            scalar_mult: |p: &RistrettoPoint, r: &[u8]| {
                p * ristretto_scalar_from_slice(r)
            },
            inverse_mult: |p: &RistrettoPoint, r: &[u8]| {
                let inv_sc = ristretto_scalar_from_slice(r).invert();
                p * inv_sc
            },
            serialize: |p: &RistrettoPoint, _: bool, out: &mut Vec<u8>| {
                ristretto_serialize(p, out)
            },
            random_element: || {
                let mut rng = OsRng;
                RistrettoPoint::random(&mut rng)
            },
            uniform_bytes: |out: &mut Vec<u8>| {
                ristretto_sample_uniform_bytes(out);
            },
            reduce_scalar: |sc: &[u8], _: bool| sc.to_vec(), // ristretto scalars are reduced automatically
            // DLEQ functions
            dleq_generate: |key: &[u8], pub_key: &RistrettoPoint, input: &RistrettoPoint, eval: &RistrettoPoint| -> [Vec<u8>; 2] {
                ristretto_dleq_gen(key, pub_key, input, eval)
            },
            dleq_verify: |pub_key: &RistrettoPoint, input: &RistrettoPoint, eval: &RistrettoPoint, proof: &[Vec<u8>; 2]| {
                ristretto_dleq_vrf(pub_key, input, eval, proof)
            },
            batch_dleq_generate: |key: &[u8], pub_key: &RistrettoPoint, inputs: &[RistrettoPoint], evals: &[RistrettoPoint]| -> [Vec<u8>; 2] {
                let [comp_m, comp_z] = ristretto_batch_compute_composities(pub_key, inputs, evals);
                ristretto_dleq_gen(key, pub_key, &comp_m, &comp_z)
            },
            batch_dleq_verify: |pub_key: &RistrettoPoint, inputs: &[RistrettoPoint], evals: &[RistrettoPoint], proof: &[Vec<u8>; 2]| {
                let [comp_m, comp_z] = ristretto_batch_compute_composities(pub_key, inputs, evals);
                ristretto_dleq_vrf(pub_key, &comp_m, &comp_z, proof)
            },
            // DLEQ functions for testing
            fixed_dleq_generate: |key: &[u8], pub_key: &RistrettoPoint, input: &RistrettoPoint, eval: &RistrettoPoint, fixed_scalar: &[u8]| -> [Vec<u8>; 2] {
                ristretto_fixed_dleq_gen(key, pub_key, input, eval, fixed_scalar)
            },
            fixed_batch_dleq_generate: |key: &[u8], pub_key: &RistrettoPoint, inputs: &[RistrettoPoint], evals: &[RistrettoPoint], fixed_scalar: &[u8]| -> [Vec<u8>; 2] {
                let [comp_m, comp_z] = ristretto_batch_compute_composities(pub_key, inputs, evals);
                ristretto_fixed_dleq_gen(key, pub_key, &comp_m, &comp_z, fixed_scalar)
            },
        }
    }
}

// generates a DLEQ proof object for RistrettoPoint objects
fn ristretto_dleq_gen(key: &[u8], pub_key: &RistrettoPoint, input: &RistrettoPoint, eval: &RistrettoPoint) -> [Vec<u8>; 2] {
    let mut out: Vec<u8> = Vec::new();
    ristretto_sample_uniform_bytes(&mut out);
    ristretto_fixed_dleq_gen(key, pub_key, input, eval, &out)
}
// generates a DLEQ proof object for RistrettoPoint objects with a fixed scalar
fn ristretto_fixed_dleq_gen(key: &[u8], pub_key: &RistrettoPoint, input: &RistrettoPoint, eval: &RistrettoPoint, fixed_scalar: &[u8]) -> [Vec<u8>; 2] {
    let t = ristretto_scalar_from_slice(fixed_scalar);
    let a = RISTRETTO_BASEPOINT_POINT * t;
    let b = input * t;
    let mut c: Vec<u8> = Vec::new();
    ristretto_dleq_hash(&[pub_key, input, eval, &a, &b], &mut c);
    let c_sc = ristretto_scalar_from_slice(&c);
    let s_sc = t - (c_sc * ristretto_scalar_from_slice(key));
    [c, s_sc.as_bytes().to_vec()]
}

// verifies a DLEQ proof object
fn ristretto_dleq_vrf(pub_key: &RistrettoPoint, input: &RistrettoPoint, eval: &RistrettoPoint, proof: &[Vec<u8>; 2]) -> bool {
    let g = RISTRETTO_BASEPOINT_POINT;
    let c_proof = &proof[0];
    let s_proof = &proof[1];
    let c_sc = ristretto_scalar_from_slice(c_proof);
    let s_sc = ristretto_scalar_from_slice(s_proof);
    let s_g = g * s_sc;
    let c_pk = pub_key * c_sc;
    let a = s_g + c_pk;
    let s_m = input * s_sc;
    let c_z = eval * c_sc;
    let b = s_m + c_z;
    let mut c_vrf: Vec<u8> = Vec::new();
    ristretto_dleq_hash(&[pub_key, input, eval, &a, &b], &mut c_vrf);
    c_proof == &c_vrf
}

fn ristretto_batch_compute_composities(pub_key: &RistrettoPoint, inputs: &[RistrettoPoint], evals: &[RistrettoPoint]) -> [RistrettoPoint; 2] {
    assert_eq!(inputs.len(), evals.len());
    let mut seed: Vec<u8> = Vec::new();
    ristretto_batch_dleq_seed(pub_key, inputs, evals, &mut seed);
    ristretto_composites(&seed, inputs, evals)
}

// computes composite ristretto255 points that are used in batch DLEQ proofs
// TODO: add these to the impl of some utility struct?
fn ristretto_composites(seed: &[u8], inputs: &[RistrettoPoint], evals: &[RistrettoPoint]) -> [RistrettoPoint; 2] {
    // init these with dummy values
    let mut comp_m: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;
    let mut comp_z: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;
    for i in 0..inputs.len() {
        let m_i = inputs[i];
        let z_i = evals[i];
        let mut i_vec = Vec::new();
        i_vec.write_u32::<LittleEndian>(i as u32).unwrap();
        let mut buf: Vec<u8> = Vec::new();
        Hkdf{}.extract(seed, &i_vec, &mut buf);
        let d_i = ristretto_scalar_from_slice(&buf);
        let dm_i = m_i * d_i;
        let dz_i = z_i * d_i;

        match i {
            0 => {
                // should always overwrite dummy values
                comp_m = dm_i;
                comp_z = dz_i;
            }
            _ => {
                comp_m = comp_m + dm_i;
                comp_z = comp_z + dz_i;
            }
        };
    }
    [comp_m, comp_z]
}

// generates a seed for deriving coefficients that are used to construct the
// composite `RistrettoPoint` objects used in batch DLEQ proofs, moves the result
// into the provided output buffer
fn ristretto_batch_dleq_seed(y: &RistrettoPoint, m: &[RistrettoPoint], z: &[RistrettoPoint], out: &mut Vec<u8>) {
    let mut inputs: Vec<&RistrettoPoint> = Vec::new();
    inputs.push(y);
    inputs.extend(m);
    inputs.extend(z);
    ristretto_dleq_hash(&inputs, out)
}

// hash inputs points for DLEQ proofs, moves the result into the provided output
// buffer
fn ristretto_dleq_hash(to_hash: &[&RistrettoPoint], out: &mut Vec<u8>) {
    let mut hash = ristretto_hash();
    let mut ser: Vec<u8> = Vec::new();
    ristretto_serialize(&RISTRETTO_BASEPOINT_POINT, &mut ser);
    for p in to_hash {
        ristretto_serialize(&p, &mut ser);
        hash.input(&ser);
    }
    copy_into(&hash.result(), out);
}

// compresses RistrettoPoints into CompressedRistretto objects ansd moves the
// result into the provided output buffer
fn ristretto_serialize(p: &RistrettoPoint, ser: &mut Vec<u8>) {
    let cmp = p.compress();
    copy_into(&cmp.to_bytes(), ser);
}

// returns the associated hash function (SHA512) for working with the
// ristretto255 prime-order group
fn ristretto_hash() -> Sha512 {
    Sha512::new()
}

// moves RISTRETTO_BYTE_LENGTH uniformly sampled bytes into the provided output buffer
fn ristretto_sample_uniform_bytes(out: &mut Vec<u8>) {
    rand_bytes(RISTRETTO_BYTE_LENGTH, out)
}

// converts a slice into an array of size RISTRETTO_BYTE_LENGTH
fn ristretto_convert_slice_to_fixed(x: &[u8]) -> [u8; RISTRETTO_BYTE_LENGTH] {
    let mut inp_bytes = [0; RISTRETTO_BYTE_LENGTH];
    let random_bytes = &x[..inp_bytes.len()];
    inp_bytes.copy_from_slice(random_bytes);
    inp_bytes
}

// Recovers a `Scalar` object from a slice
fn ristretto_scalar_from_slice(x: &[u8]) -> Scalar {
    Scalar::from_bytes_mod_order(ristretto_convert_slice_to_fixed(x))
}

#[cfg(test)]
mod tests {
    use super::{PrimeOrderGroup,ristretto_scalar_from_slice,ristretto_convert_slice_to_fixed};
    use super::err_deserialization;

    #[test]
    fn ristretto_serialization() {
        let pog = PrimeOrderGroup::ristretto_255();
        let p = (pog.random_element)();
        let mut ser: Vec<u8> = Vec::new();
        (pog.serialize)(&p, true, &mut ser);
        let p_chk = (pog.deserialize)(&ser)
                        .expect("Failed to deserialize point");
        assert_eq!(p, p_chk)
    }

    #[test]
    fn ristretto_err_ser() {
        // trigger error if buffer is malformed
        let pog = PrimeOrderGroup::ristretto_255();
        let mut ser: Vec<u8> = Vec::new();
        (pog.serialize)(&(pog.random_element)(), true, &mut ser);
        // modify the buffer
        ser[0] = ser[0]+2;
        ser[1] = ser[1]+1;
        ser[2] = ser[2]+1;
        ser[3] = ser[3]+1;
        match (pog.deserialize)(&ser) {
            Ok(_) => panic!("test should have failed"),
            Err(e) => assert_eq!(e.kind(), err_deserialization().kind())
        }
    }

    #[test]
    fn ristretto_point_mult() {
        let pog = PrimeOrderGroup::ristretto_255();
        let p = (pog.random_element)();
        let mut r1: Vec<u8> = Vec::new();
        let mut r2: Vec<u8> = Vec::new();
        (pog.uniform_bytes)(&mut r1);
        (pog.uniform_bytes)(&mut r2);
        let r1_p = (pog.scalar_mult)(&p, &r1);
        let r2_p = (pog.scalar_mult)(&p, &r2);
        let add_p = (pog.add)(&r1_p, &r2_p);
        let r1_sc = ristretto_scalar_from_slice(&r1);
        let r2_sc = ristretto_scalar_from_slice(&r2);
        let r1_r2_sc = r1_sc + r2_sc;
        let mult_p = (pog.scalar_mult)(&p, &r1_r2_sc.to_bytes());
        assert_eq!((pog.is_equal)(&add_p, &mult_p), true);
    }

    #[test]
    fn ristretto_encode_to_group() {
        let pog = PrimeOrderGroup::ristretto_255();
        let buf: [u8; 32] = [0; 32];
        let p = (pog.encode_to_group)(&buf);
        let mut ser: Vec<u8> = Vec::new();
        (pog.serialize)(&p, true, &mut ser);
        // TODO: use official test vector
        let test_arr: [u8; 32] = [
            106, 149, 254, 191, 64, 250, 76, 160, 174, 188, 62, 185, 131, 87,
            159, 9, 240, 147, 1, 218, 222, 46, 118, 3, 46, 99, 181, 131, 28, 64,
            18, 101
        ];
        assert_eq!(ser, test_arr.to_vec())
    }

    #[test]
    fn ristretto_rand_bytes() {
        let pog = PrimeOrderGroup::ristretto_255();
        let mut r: Vec<u8> = Vec::new();
        (pog.uniform_bytes)(&mut r);
        assert_eq!(r.len(), pog.byte_length);
        let fixed = ristretto_convert_slice_to_fixed(&r);
        assert_eq!(fixed.len(), pog.byte_length);
        for i in 0..pog.byte_length {
            assert_eq!(r[i], fixed[i]);
        }
    }

    #[test]
    fn ristretto_inverse_mult() {
        let pog = PrimeOrderGroup::ristretto_255();
        let mut r: Vec<u8> = Vec::new();
        (pog.uniform_bytes)(&mut r);
        let inv = ristretto_scalar_from_slice(&r).invert().to_bytes();
        let p = (pog.random_element)();
        let r_p = (pog.scalar_mult)(&p, &r);
        let inv_r_p = (pog.scalar_mult)(&r_p, &inv);
        assert_eq!(inv_r_p, p);
    }

    #[test]
    fn ristretto_dleq() {
        let pog = PrimeOrderGroup::ristretto_255();

        // mimic oprf operations
        let mut key: Vec<u8> = Vec::new();
        (pog.uniform_bytes)(&mut key);
        let pub_key = (pog.scalar_mult)(&pog.generator, &key);
        let m = (pog.random_element)();
        let z = (pog.scalar_mult)(&m, &key);

        // generate proof
        let proof = (pog.dleq_generate)(&key, &pub_key, &m, &z);
        assert_eq!(proof.len(), 2);

        // verify proof
        assert_eq!((pog.dleq_verify)(&pub_key, &m, &z, &proof), true);
    }

    #[test]
    fn ristretto_batch_dleq() {
        let pog = PrimeOrderGroup::ristretto_255();

        // mimic oprf operations
        let mut key: Vec<u8> = Vec::new();
        (pog.uniform_bytes)(&mut key);
        let pub_key = (pog.scalar_mult)(&pog.generator, &key);

        let mut inputs = Vec::new();
        let mut evals = Vec::new();
        for _ in 0..10 {
            let m = (pog.random_element)();
            inputs.push(m);
            evals.push((pog.scalar_mult)(&m, &key));
        }

        // generate proof
        let proof = (pog.batch_dleq_generate)(&key, &pub_key, &inputs, &evals);
        assert_eq!(proof.len(), 2);

        // verify proof
        assert_eq!((pog.batch_dleq_verify)(&pub_key, &inputs, &evals, &proof), true);
    }

    #[test]
    fn ristretto_dleq_fail() {
        let pog = PrimeOrderGroup::ristretto_255();

        // mimic oprf operations
        let mut key_1: Vec<u8> = Vec::new();
        let mut key_2: Vec<u8> = Vec::new();
        (pog.uniform_bytes)(&mut key_1);
        (pog.uniform_bytes)(&mut key_2);
        let pub_key_1 = (pog.scalar_mult)(&pog.generator, &key_1);
        let pub_key_2 = (pog.scalar_mult)(&pog.generator, &key_2);
        let m = (pog.random_element)();
        let z_1 = (pog.scalar_mult)(&m, &key_1);
        let z_2 = (pog.scalar_mult)(&m, &key_2);

        // generate proof
        let proof = (pog.dleq_generate)(&key_1, &pub_key_1, &m, &z_2);
        assert_eq!(proof.len(), 2);

        // verify proof
        assert_eq!((pog.dleq_verify)(&pub_key_1, &m, &z_2, &proof), false);

        // generate proof
        let proof = (pog.dleq_generate)(&key_1, &pub_key_2, &m, &z_1);
        assert_eq!(proof.len(), 2);

        // verify proof
        assert_eq!((pog.dleq_verify)(&pub_key_2, &m, &z_1, &proof), false);
    }

    #[test]
    fn ristretto_batch_dleq_fail_bad_batch() {
        let pog = PrimeOrderGroup::ristretto_255();

        // mimic oprf operations
        let mut key: Vec<u8> = Vec::new();
        (pog.uniform_bytes)(&mut key);
        let pub_key = (pog.scalar_mult)(&pog.generator, &key);

        let mut inputs = Vec::new();
        let mut evals = Vec::new();
        for _ in 0..10 {
            let m = (pog.random_element)();
            inputs.push(m);
            evals.push((pog.scalar_mult)(&m, &key));
        }

        // modify a single point
        let mut bad_key: Vec<u8> = Vec::new();
        (pog.uniform_bytes)(&mut bad_key);
        evals[2] = (pog.scalar_mult)(&inputs[2], &bad_key);

        // generate proof
        let proof = (pog.batch_dleq_generate)(&key, &pub_key, &inputs, &evals);
        assert_eq!(proof.len(), 2);

        // verify proof
        assert_eq!((pog.batch_dleq_verify)(&pub_key, &inputs, &evals, &proof), false);
    }
}