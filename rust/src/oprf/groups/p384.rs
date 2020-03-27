//! The `p384` module allows creating a `PrimeOrderGroup` object using the NIST
//! P-384 elliptic curve.
//!
//! # Example
//!
//! ```
//! use voprf_rs::oprf::groups::PrimeOrderGroup;
//! let pog = PrimeOrderGroup::p384_old();
//! ```

use super::{PrimeOrderGroup,GroupID};
use super::super::super::utils::copy_into;
use hkdf_sha512::Hkdf;

use ecc_rs::point::AffinePoint;
use ecc_rs::point::{P384,Encoded};

use sha2::Sha512;
use sha2::Digest;
use byteorder::{BigEndian, WriteBytesExt};
use rand_core::OsRng;
use rand_core::RngCore;
use num::{BigInt,BigUint};
use num_bigint::Sign;

const P384_BYTE_LENGTH: usize = 48;

/// Wraps the Montgomery encoded `AffinePoint` struct from ecc-rs.
pub type NistPoint = AffinePoint<Encoded>;

/// Instantiation of `PrimeOrderGroup` for NIST P-384 curve
impl PrimeOrderGroup<NistPoint,Sha512> {
    /// Returns an instance of PrimeOrderGroup that allows performing (V)OPRF
    /// operations using the prime-order group associated the NIST P-384 curve.
    ///
    /// # Example
    ///
    /// ```
    /// use voprf_rs::oprf::groups::PrimeOrderGroup;
    /// let pog = PrimeOrderGroup::p384_old();
    /// ```
    pub fn p384_old() -> PrimeOrderGroup<NistPoint,Sha512> {
        PrimeOrderGroup{
            group_id: GroupID::P384Old,
            generator: NistPoint::get_generator(P384).unwrap(),
            byte_length: P384_BYTE_LENGTH,
            hash: || p384_hash(),
            deserialize: |buf: &[u8]| NistPoint::new(P384).unwrap().deserialize(buf),
            encode_to_group: |buf: &[u8]| NistPoint::new(P384).unwrap().hash_to_curve(buf, "RFCXXXX-VOPRF".to_string()),
            is_valid: |p: &NistPoint| p.is_valid(),
            is_equal: |p1: &NistPoint, p2: &NistPoint| p1.equals(p2),
            add: |p1: &NistPoint, p2: &NistPoint| p1.to_jacobian().add(&p2.to_jacobian()).to_affine(),
            scalar_mult: |p: &NistPoint, r: &[u8]| p.scalar_mul(r).to_affine(),
            inverse_mult: |p: &NistPoint, r: &[u8]| p.inv_scalar_mul(r).to_affine(),
            serialize: |p: &NistPoint, compress: bool, out: &mut Vec<u8>| nist_serialize(p, compress, out),
            random_element: || {
                let mut rng = OsRng;
                let mut alpha = vec![0; P384_BYTE_LENGTH];
                rng.fill_bytes(&mut alpha);
                NistPoint::new(P384).unwrap().hash_to_curve(&alpha, "RFCXXXX-VOPRF".to_string())
            },
            uniform_bytes: |out: &mut Vec<u8>| {
                let bytes = NistPoint::new(P384).unwrap()
                                        .uniform_bytes_from_field().unwrap();
                copy_into(&bytes, out);
            },
            reduce_scalar: |sc: &[u8], pve: bool| NistPoint::new(P384).unwrap()
                                                        .reduce_scalar(sc, pve),
            // DLEQ functions
            dleq_generate: |key: &[u8], pub_key: &NistPoint, input: &NistPoint, eval: &NistPoint| -> [Vec<u8>; 2] {
                p384_dleq_gen(key, pub_key, input, eval)
            },
            dleq_verify: |pub_key: &NistPoint, input: &NistPoint, eval: &NistPoint, proof: &[Vec<u8>; 2]| {
                p384_dleq_vrf(pub_key, input, eval, proof)
            },
            batch_dleq_generate: |key: &[u8], pub_key: &NistPoint, inputs: &[NistPoint], evals: &[NistPoint]| -> [Vec<u8>; 2] {
                let [comp_m, comp_z] = p384_batch_compute_composities(pub_key, inputs, evals);
                p384_dleq_gen(key, pub_key, &comp_m, &comp_z)
            },
            batch_dleq_verify: |pub_key: &NistPoint, inputs: &[NistPoint], evals: &[NistPoint], proof: &[Vec<u8>; 2]| {
                let [comp_m, comp_z] = p384_batch_compute_composities(pub_key, inputs, evals);
                p384_dleq_vrf(pub_key, &comp_m, &comp_z, proof)
            },
            // DLEQ functions for testing
            fixed_dleq_generate: |key: &[u8], pub_key: &NistPoint, input: &NistPoint, eval: &NistPoint, fixed_scalar: &[u8]| -> [Vec<u8>; 2] {
                p384_fixed_dleq_gen(key, pub_key, input, eval, fixed_scalar)
            },
            fixed_batch_dleq_generate: |key: &[u8], pub_key: &NistPoint, inputs: &[NistPoint], evals: &[NistPoint], fixed_scalar: &[u8]| -> [Vec<u8>; 2] {
                let [comp_m, comp_z] = p384_batch_compute_composities(pub_key, inputs, evals);
                p384_fixed_dleq_gen(key, pub_key, &comp_m, &comp_z, fixed_scalar)
            },
        }
    }
}

// serialize the NIST curve point
fn nist_serialize(p: &NistPoint, compress: bool, out: &mut Vec<u8>) {
    let bytes = p.serialize(compress);
    copy_into(&bytes, out);
}

// generates a DLEQ proof object for NistPoint objects
fn p384_dleq_gen(key: &[u8], pub_key: &NistPoint, input: &NistPoint, eval: &NistPoint) -> [Vec<u8>; 2] {
    let mut t: Vec<u8> = Vec::new();
    p384_sample_uniform_bytes(&mut t);
    p384_fixed_dleq_gen(key, pub_key, input, eval, &t)
}

// generates a DLEQ proof object for NistPoint objects with fixed scalar input
fn p384_fixed_dleq_gen(key: &[u8], pub_key: &NistPoint, input: &NistPoint, eval: &NistPoint, t: &[u8]) -> [Vec<u8>; 2] {
    let gen = NistPoint::get_generator(P384).unwrap();
    let a = gen.scalar_mul(t).to_affine();
    let b = input.scalar_mul(t).to_affine();
    let mut c = vec![0; P384_BYTE_LENGTH];
    compute_expanded_dleq_challenge(&[pub_key, input, eval, &a, &b], &mut c);
    let c_sc = BigInt::from_bytes_be(Sign::Plus, &c);
    let t_sc = BigInt::from_bytes_be(Sign::Plus, t);
    let k_sc = BigInt::from_bytes_be(Sign::Plus, &key);
    let s_sc = t_sc - (c_sc * k_sc);
    let (bi_sgn, bytes) = s_sc.to_bytes_be();
    [gen.reduce_scalar(&c, true), gen.reduce_scalar(&bytes, bi_sgn == Sign::Plus)]
}

fn p384_dleq_vrf(pub_key: &NistPoint, input: &NistPoint, eval: &NistPoint, proof: &[Vec<u8>; 2]) -> bool {
    let g = NistPoint::get_generator(P384).unwrap();
    let c_proof = &proof[0];
    let s_proof = &proof[1];
    let s_g = g.scalar_mul(s_proof);
    let c_pk = pub_key.scalar_mul(c_proof);
    let a = s_g.add(&c_pk).to_affine();
    let s_m = input.scalar_mul(s_proof);
    let c_z = eval.scalar_mul(c_proof);
    let b = s_m.add(&c_z).to_affine();
    let mut c_vrf = vec![0; P384_BYTE_LENGTH];
    compute_expanded_dleq_challenge(&[pub_key, input, eval, &a, &b], &mut c_vrf);
    return c_proof == &g.reduce_scalar(&c_vrf, true);
}

fn p384_batch_compute_composities(pub_key: &NistPoint, inputs: &[NistPoint], evals: &[NistPoint]) -> [NistPoint; 2] {
    assert_eq!(inputs.len(), evals.len());
    let mut seed: Vec<u8> = Vec::new();
    p384_batch_dleq_seed(pub_key, inputs, evals, &mut seed);
    p384_compute_composites(&seed, inputs, evals)
}

// hash inputs points for DLEQ proofs into the output buffer `out`
fn p384_dleq_hash(to_hash: &[&NistPoint], out: &mut Vec<u8>) {
    let mut hash = p384_hash();
    let mut ser: Vec<u8> = Vec::new();
    nist_serialize(&NistPoint::get_generator(P384).unwrap(), true, &mut ser);
    hash.input(&ser);
    for p in to_hash {
        nist_serialize(&p, true, &mut ser);
        hash.input(&ser);
    }
    copy_into(&hash.result(), out);
}

// computes composite ristretto255 points that are used in batch DLEQ proofs
// TODO: add these to the impl of some utility struct?
fn p384_compute_composites(seed: &[u8], inputs: &[NistPoint], evals: &[NistPoint]) -> [NistPoint; 2] {
    // init these with dummy values
    let p = NistPoint::new(P384).unwrap();
    let mut comp_m = p.to_jacobian();
    let mut comp_z = p.to_jacobian();
    let label = "voprf_batch_dleq".as_bytes();
    let mut ctr = 0; // used for labelling hkdf implementation
    let mut i = 0; // counts the number of items to process
    while i < inputs.len() {
        let m_i = &inputs[i];
        let z_i = &evals[i];
        let mut ctr_vec = Vec::new();
        ctr_vec.write_u32::<BigEndian>(ctr as u32).unwrap();
        ctr_vec.extend_from_slice(&label);
        ctr = ctr + 1;

        // sample coefficient
        let mut d_i = vec![0; P384_BYTE_LENGTH];
        Hkdf{}.expand(seed, &ctr_vec, &mut d_i);
        // reject if greater than N
        if !verify_scalar_size(&d_i) {
            continue;
        }
        let dm_i = m_i.scalar_mul(&d_i);
        let dz_i = z_i.scalar_mul(&d_i);

        let (m_i, z_i) = match i {
            0 => (dm_i, dz_i), // overwrite dummy values
            _ => (comp_m.add(&dm_i), comp_z.add(&dz_i)),
        };
        comp_m = m_i;
        comp_z = z_i;
        i = i+1;
    }
    [comp_m.to_affine(), comp_z.to_affine()]
}

// generates a seed for deriving coefficients that are used to construct the
// composite `RistrettoPoint` objects used in batch DLEQ proofs, moves the result
// into the provided output buffer
fn p384_batch_dleq_seed(y: &NistPoint, m: &[NistPoint], z: &[NistPoint], out: &mut Vec<u8>) {
    let mut inputs: Vec<&NistPoint> = Vec::new();
    inputs.push(y);
    inputs.extend(m);
    inputs.extend(z);
    p384_dleq_hash(&inputs, out)
}

// Samples bytes uniformly corresponding to scalars in the base field associated
// with P-384
fn p384_sample_uniform_bytes(out: &mut Vec<u8>) {
    let bytes = NistPoint::new(P384).unwrap().uniform_bytes_from_field().unwrap();
    copy_into(&bytes, out)
}

// Samples the random challenge value `c` used in the NI version of the DLEQ
// proof system
fn compute_expanded_dleq_challenge(inputs: &[&NistPoint], c: &mut Vec<u8>) {
    let mut seed: Vec<u8> = Vec::new();
    p384_dleq_hash(inputs, &mut seed);
    let label = "voprf_dleq_challenge".as_bytes();
    let mut ctr = 0;
    loop {
        let mut info = Vec::new();
        info.write_u32::<BigEndian>(ctr as u32).unwrap();
        info.extend_from_slice(&label);
        Hkdf{}.expand(&seed, &info, c);
        if !(verify_scalar_size(c)) {
            ctr = ctr+1;
            continue;
        }
        break;
    }
}

// returns true if the scalar is within the order of the base field, and false
// otherwise.
fn verify_scalar_size(c: &[u8]) -> bool {
    let p = NistPoint::new(P384).unwrap();
    let reduced = p.reduce_scalar(&c, true);
    BigUint::from_bytes_be(&reduced) == BigUint::from_bytes_be(&c)
}

// returns the associated hash function (SHA512) for working with the p384
// prime-order group
fn p384_hash() -> Sha512 {
    Sha512::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use num::BigUint;

    #[test]
    fn p384_serialization() {
        let pog = PrimeOrderGroup::p384_old();
        let p = (pog.random_element)();
        let mut ser: Vec<u8> = Vec::new();
        (pog.serialize)(&p, true, &mut ser);
        let p_chk = (pog.deserialize)(&ser)
                        .expect("Failed to deserialize point");
        assert!(p.equals(&p_chk))
    }

    #[test]
    #[should_panic]
    fn p384_err_ser() {
        // trigger error if buffer is malformed
        let pog = PrimeOrderGroup::p384_old();
        let mut ser: Vec<u8> = Vec::new();
        (pog.serialize)(&(pog.random_element)(), true, &mut ser);
        // modify the buffer
        ser[0] = ser[0]+1;
        ser[1] = ser[1]+1;
        ser[2] = ser[2]+1;
        ser[3] = ser[3]+1;
        match (pog.deserialize)(&ser) {
            Ok(_) => panic!("test should have failed"),
            _ => assert!(true)
        }
    }

    #[test]
    fn p384_point_mult() {
        let pog = PrimeOrderGroup::p384_old();
        let p = (pog.random_element)();
        let mut r1: Vec<u8> = Vec::new();
        let mut r2: Vec<u8> = Vec::new();
        (pog.uniform_bytes)(&mut r1);
        (pog.uniform_bytes)(&mut r2);
        let r1_p = (pog.scalar_mult)(&p, &r1);
        let r2_p = (pog.scalar_mult)(&p, &r2);
        let add_p = (pog.add)(&r1_p, &r2_p);
        let r1_sc = BigUint::from_bytes_be(&r1);
        let r2_sc = BigUint::from_bytes_be(&r2);
        let r1_r2_sc = p.reduce_scalar(&(r1_sc + r2_sc).to_bytes_be(), true);
        let mult_p = (pog.scalar_mult)(&p, &r1_r2_sc);
        assert_eq!((pog.is_equal)(&add_p, &mult_p), true);
    }

    #[test]
    fn p384_encode_to_group() {
        let pog = PrimeOrderGroup::p384_old();
        let buf: [u8; 32] = [0; 32];
        let p = (pog.encode_to_group)(&buf);
        let mut ser: Vec<u8> = Vec::new();
        (pog.serialize)(&p, true, &mut ser);
        // TODO: use official test vector
        let test_arr: [u8; 1+P384_BYTE_LENGTH] = [
            3, 51, 64, 101, 130, 28, 15, 150, 165, 237, 149, 238, 250,
            119, 10, 66, 138, 184, 105, 79, 130, 49, 134, 39, 251, 135,
            93, 198, 174, 115, 240, 73, 218, 116, 76, 210, 232, 7, 41,
            173, 220, 224, 221, 156, 121, 28, 214, 145, 61
        ];
        assert_eq!(ser, test_arr.to_vec())
    }

    #[test]
    fn p384_rand_bytes() {
        let pog = PrimeOrderGroup::p384_old();
        let mut r: Vec<u8> = Vec::new();
        (pog.uniform_bytes)(&mut r);
        assert_eq!(r.len(), pog.byte_length);
        let fixed = p384_convert_slice_to_fixed(&r);
        assert_eq!(fixed.len(), pog.byte_length);
        for i in 0..pog.byte_length {
            assert_eq!(r[i], fixed[i]);
        }
    }

    #[test]
    fn p384_inverse_mult() {
        let pog = PrimeOrderGroup::p384_old();
        let mut r: Vec<u8> = Vec::new();
        (pog.uniform_bytes)(&mut r);
        let p = (pog.random_element)();
        let r_p = (pog.scalar_mult)(&p, &r);
        let inv_r_p = (pog.inverse_mult)(&r_p, &r);
        assert!(inv_r_p.equals(&p));
    }

    #[test]
    fn p384_dleq() {
        let pog = PrimeOrderGroup::p384_old();

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
    fn p384_batch_dleq() {
        let pog = PrimeOrderGroup::p384_old();

        // mimic oprf operations
        let mut key: Vec<u8> = Vec::new();
        (pog.uniform_bytes)(&mut key);
        let pub_key = (pog.scalar_mult)(&pog.generator, &key);

        let mut inputs = Vec::new();
        let mut evals = Vec::new();
        for i in 0..10 {
            let m = (pog.random_element)();
            inputs.push(m);
            evals.push((pog.scalar_mult)(&inputs[i], &key));
        }

        // generate proof
        let proof = (pog.batch_dleq_generate)(&key, &pub_key, &inputs, &evals);
        assert_eq!(proof.len(), 2);

        // verify proof
        assert_eq!((pog.batch_dleq_verify)(&pub_key, &inputs, &evals, &proof), true);
    }

    #[test]
    fn p384_dleq_fail() {
        let pog = PrimeOrderGroup::p384_old();

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
    fn p384_batch_dleq_fail_bad_batch() {
        let pog = PrimeOrderGroup::p384_old();

        // mimic oprf operations
        let mut key: Vec<u8> = Vec::new();
        (pog.uniform_bytes)(&mut key);
        let pub_key = (pog.scalar_mult)(&pog.generator, &key);

        let mut inputs = Vec::new();
        let mut evals = Vec::new();
        for i in 0..10 {
            let m = (pog.random_element)();
            inputs.push(m);
            evals.push((pog.scalar_mult)(&inputs[i], &key));
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

    // converts a slice into an array of size P384_BYTE_LENGTH
    fn p384_convert_slice_to_fixed(x: &[u8]) -> [u8; P384_BYTE_LENGTH] {
        let mut inp_bytes = [0; P384_BYTE_LENGTH];
        let random_bytes = &x[..inp_bytes.len()];
        inp_bytes.copy_from_slice(random_bytes);
        inp_bytes
    }
}