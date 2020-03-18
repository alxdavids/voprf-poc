//! p384-redox module
use super::PrimeOrderGroup;
use super::super::super::utils::copy_into;
use hkdf_sha512::Hkdf;

use h2c_rust_ref::{HashToCurve, P384_SHA512_SSWU_RO_};
use h2c_rust_ref::redox_ecc::weierstrass;
use h2c_rust_ref::redox_ecc::weierstrass::Scalar;
use h2c_rust_ref::redox_ecc::field::Field;
use h2c_rust_ref::redox_ecc::ellipticcurve::EllipticCurve;
use h2c_rust_ref::redox_ecc::instances::{GetCurve, P384};
use h2c_rust_ref::redox_ecc::ops::{Serialize, Deserialize};

use sha2::Sha512;
use sha2::Digest;
use num_bigint::{BigInt, BigUint, Sign};
use byteorder::{BigEndian, WriteBytesExt};
use rand_core::OsRng;
use rand_core::RngCore;

const P384_BYTE_LENGTH: usize = 48;

/// Point type for redox-ecc
pub type RedoxPoint = <weierstrass::Curve as EllipticCurve>::Point;

/// Instantiation of `PrimeOrderGroup` for NIST P-384 curve
impl PrimeOrderGroup<RedoxPoint,Sha512> {
    /// Returns an instance of PrimeOrderGroup that allows performing
    /// (V)OPRF operations using the prime-order group associated the
    /// NIST P-384 curve.
    ///
    /// # Example
    ///
    /// ```
    /// use voprf_rs::oprf::groups::PrimeOrderGroup;
    /// let pog = PrimeOrderGroup::p384();
    /// ```
    pub fn p384_redox() -> PrimeOrderGroup<RedoxPoint,Sha512> {
        PrimeOrderGroup{
            generator: P384.get().get_generator(),
            byte_length: P384_BYTE_LENGTH,
            hash: || p384_hash(),
            deserialize: |buf: &[u8]| P384.get().from_bytes_be(buf),
            encode_to_group: |buf: &[u8]| hash_to_curve(buf),
            is_valid: |p: &RedoxPoint| P384.get().is_on_curve(p),
            is_equal: |p1: &RedoxPoint, p2: &RedoxPoint| p1 == p2,
            add: |p1: &RedoxPoint, p2: &RedoxPoint| p1 + p2,
            scalar_mult: |p: &RedoxPoint, r: &[u8]| {
                let modulus = P384.get().get_field()
                                .get_modulus().to_biguint().unwrap();
                let r_sc = to_redox_scalar(r, &modulus);
                p * r_sc
            },
            inverse_mult: |p: &RedoxPoint, r: &[u8]| {
                let modulus = P384.get().get_field()
                                .get_modulus().to_biguint().unwrap();
                let one_sc = to_redox_scalar(&vec![1], &modulus);
                let r_sc = to_redox_scalar(r, &modulus);
                let inv_sc = one_sc/r_sc; // 1_u32 didn't work?
                p * inv_sc
            },
            serialize: |p: &RedoxPoint, compress: bool, out: &mut Vec<u8>| nist_serialize(p, compress, out),
            random_element: || {
                let mut alpha = vec![0; P384_BYTE_LENGTH];
                p384_fill_uniform_bytes(&mut alpha);
                hash_to_curve(&alpha)
            },
            uniform_bytes: |out: &mut Vec<u8>| {
                let mut alpha = vec![0; P384_BYTE_LENGTH];
                p384_fill_uniform_bytes(&mut alpha);
                copy_into(&alpha, out);
            },
            reduce_scalar: |_: &[u8], _: bool| unimplemented!(),
            // DLEQ functions
            dleq_generate: |key: &[u8], pub_key: &RedoxPoint, input: &RedoxPoint, eval: &RedoxPoint| -> [Vec<u8>; 2] {
                p384_dleq_gen(key, pub_key, input, eval)
            },
            dleq_verify: |pub_key: &RedoxPoint, input: &RedoxPoint, eval: &RedoxPoint, proof: &[Vec<u8>; 2]| {
                p384_dleq_vrf(pub_key, input, eval, proof)
            },
            batch_dleq_generate: |key: &[u8], pub_key: &RedoxPoint, inputs: &[RedoxPoint], evals: &[RedoxPoint]| -> [Vec<u8>; 2] {
                let [comp_m, comp_z] = p384_batch_compute_composities(pub_key, inputs, evals);
                p384_dleq_gen(key, pub_key, &comp_m, &comp_z)
            },
            batch_dleq_verify: |pub_key: &RedoxPoint, inputs: &[RedoxPoint], evals: &[RedoxPoint], proof: &[Vec<u8>; 2]| {
                let [comp_m, comp_z] = p384_batch_compute_composities(pub_key, inputs, evals);
                p384_dleq_vrf(pub_key, &comp_m, &comp_z, proof)
            },
            // DLEQ functions for testing
            fixed_dleq_generate: |key: &[u8], pub_key: &RedoxPoint, input: &RedoxPoint, eval: &RedoxPoint, fixed_scalar: &[u8]| -> [Vec<u8>; 2] {
                p384_fixed_dleq_gen(key, pub_key, input, eval, fixed_scalar)
            },
            fixed_batch_dleq_generate: |key: &[u8], pub_key: &RedoxPoint, inputs: &[RedoxPoint], evals: &[RedoxPoint], fixed_scalar: &[u8]| -> [Vec<u8>; 2] {
                let [comp_m, comp_z] = p384_batch_compute_composities(pub_key, inputs, evals);
                p384_fixed_dleq_gen(key, pub_key, &comp_m, &comp_z, fixed_scalar)
            },
        }
    }
}

// serialize the NIST curve point
fn nist_serialize(p: &RedoxPoint, compress: bool, out: &mut Vec<u8>) {
    let mut p_clone = p.clone();
    p_clone.set_compression(compress);
    let bytes = p.to_bytes_be();
    copy_into(&bytes, out);
}

// deterministically hashes the input bytes to a random point on the
// curve
fn hash_to_curve(buf: &[u8]) -> RedoxPoint {
    let h = P384_SHA512_SSWU_RO_.get("RFCXXXX-VOPRF".as_bytes());
    let mut p: RedoxPoint = h.hash(buf);
    p.normalize();
    p
}

// generates a DLEQ proof object for RedoxPoint objects
fn p384_dleq_gen(key: &[u8], pub_key: &RedoxPoint, input: &RedoxPoint, eval: &RedoxPoint) -> [Vec<u8>; 2] {
    let mut t: Vec<u8> = Vec::new();
    p384_fill_uniform_bytes(&mut t);
    p384_fixed_dleq_gen(key, pub_key, input, eval, &t)
}

// generates a DLEQ proof object for RedoxPoint objects with fixed
// scalar input
fn p384_fixed_dleq_gen(key: &[u8], pub_key: &RedoxPoint, input: &RedoxPoint, eval: &RedoxPoint, t: &[u8]) -> [Vec<u8>; 2] {
    let curve = P384.get();
    let gen = curve.get_generator();
    let modulus = curve.get_field().get_modulus().to_biguint().unwrap();
    let t_sc = to_redox_scalar(t, &modulus);
    let a = &gen * &t_sc;
    let b = input * &t_sc;
    let mut c = vec![0; P384_BYTE_LENGTH];
    p384_compute_expanded_dleq_challenge(&[pub_key, input, eval, &a, &b], &mut c);
    let c_sc = to_redox_scalar(&c, &modulus);
    let k_sc = to_redox_scalar(key, &modulus);
    let s_sc = t_sc - (c_sc * k_sc);
    [c, s_sc.to_bytes_be()]
}

fn p384_dleq_vrf(pub_key: &RedoxPoint, input: &RedoxPoint, eval: &RedoxPoint, proof: &[Vec<u8>; 2]) -> bool {
    let curve = P384.get();
    let gen = curve.get_generator();
    let modulus = curve.get_field().get_modulus().to_biguint().unwrap();
    let c_proof = &proof[0];
    let s_proof = &proof[1];
    let c_sc = to_redox_scalar(c_proof, &modulus);
    let s_sc = to_redox_scalar(s_proof, &modulus);
    let s_g = &gen * &s_sc;
    let c_pk = pub_key * &c_sc;
    let a = s_g + c_pk;
    let s_m = input * &s_sc;
    let c_z = eval * &c_sc;
    let b = s_m + c_z;
    let mut c_vrf = vec![0; P384_BYTE_LENGTH];
    p384_compute_expanded_dleq_challenge(&[pub_key, input, eval, &a, &b], &mut c_vrf);
    c_proof == &c_vrf
}

fn p384_batch_compute_composities(pub_key: &RedoxPoint, inputs: &[RedoxPoint], evals: &[RedoxPoint]) -> [RedoxPoint; 2] {
    assert_eq!(inputs.len(), evals.len());
    let mut seed: Vec<u8> = Vec::new();
    p384_batch_dleq_seed(pub_key, inputs, evals, &mut seed);
    p384_compute_composites(&seed, inputs, evals)
}

// hash inputs points for DLEQ proofs into the output buffer `out`
fn p384_dleq_hash(to_hash: &[&RedoxPoint], out: &mut Vec<u8>) {
    let mut hash = p384_hash();
    let mut ser: Vec<u8> = Vec::new();
    nist_serialize(&P384.get().get_generator(), true, &mut ser);
    hash.input(&ser);
    for p in to_hash {
        nist_serialize(&p, true, &mut ser);
        hash.input(&ser);
    }
    copy_into(&hash.result(), out);
}

// computes composite curve points that are used in batch DLEQ
// proofs TODO: add these to the impl of some utility struct?
fn p384_compute_composites(seed: &[u8], inputs: &[RedoxPoint], evals: &[RedoxPoint]) -> [RedoxPoint; 2] {
    // init these with dummy values
    let p384_curve = P384.get();
    let modulus = p384_curve.get_field().get_modulus().to_biguint().unwrap();
    let mut comp_m = p384_curve.get_generator(); // dummy point
    let mut comp_z = p384_curve.get_generator(); // dummy point
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
        if !verify_scalar_size(&d_i, modulus.clone()) {
            continue;
        }
        let d_i_sc = to_redox_scalar(&d_i, &modulus);
        let dm_i = m_i * &d_i_sc;
        let dz_i = z_i * &d_i_sc;

        let (m_i, z_i) = match i {
            0 => (dm_i, dz_i), // overwrite dummy values
            _ => (comp_m + dm_i, comp_z + dz_i),
        };
        comp_m = m_i;
        comp_z = z_i;
        i = i+1;
    }
    [comp_m, comp_z]
}

// generates a seed for deriving coefficients that are used to construct
// the composite point objects used in batch DLEQ proofs, moves the
// result into the provided output buffer
fn p384_batch_dleq_seed(y: &RedoxPoint, m: &[RedoxPoint], z: &[RedoxPoint], out: &mut Vec<u8>) {
    let mut inputs: Vec<&RedoxPoint> = Vec::new();
    inputs.push(y);
    inputs.extend(m);
    inputs.extend(z);
    p384_dleq_hash(&inputs, out)
}

// Fills the input slice with random bytes
fn p384_fill_uniform_bytes(out: &mut Vec<u8>) {
    let mut rng = OsRng;
    let mut alpha = vec![0; P384_BYTE_LENGTH];
    rng.fill_bytes(&mut alpha);
    copy_into(&alpha, out);
}

// Samples the random challenge value `c` used in the NI version of the
// DLEQ proof system
fn p384_compute_expanded_dleq_challenge(inputs: &[&RedoxPoint], c: &mut Vec<u8>) {
    let p384_curve_modulus = P384.get().get_field()
                                .get_modulus().to_biguint().unwrap();
    let mut seed: Vec<u8> = Vec::new();
    p384_dleq_hash(inputs, &mut seed);
    let label = "voprf_dleq_challenge".as_bytes();
    let mut ctr = 0;
    loop {
        let mut info = Vec::new();
        info.write_u32::<BigEndian>(ctr as u32).unwrap();
        info.extend_from_slice(&label);
        Hkdf{}.expand(&seed, &info, c);
        if !(verify_scalar_size(c, p384_curve_modulus.clone())) {
            ctr = ctr+1;
            continue;
        }
        break;
    }
}

// returns true if the scalar is within the order of the base field, and
// false otherwise.
fn verify_scalar_size(c: &[u8], modulus: BigUint) -> bool {
    BigUint::from_bytes_be(c) < modulus
}

// converts a u8 value into a redox scalar for internal operations
fn to_redox_scalar(val: &[u8], modulus: &BigUint) -> Scalar {
    Scalar::new(BigInt::from_bytes_be(Sign::Plus, val), modulus)
}

// returns the associated hash function (SHA512) for working with the
// p384 prime-order group
fn p384_hash() -> Sha512 {
    Sha512::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use num::BigUint;

    #[test]
    fn p384_redox_serialization() {
        let pog = PrimeOrderGroup::p384();
        let p = (pog.random_element)();
        let mut ser: Vec<u8> = Vec::new();
        (pog.serialize)(&p, true, &mut ser);
        let p_chk = (pog.deserialize)(&ser)
                        .expect("Failed to deserialize point");
        assert!(p.equals(&p_chk))
    }

    #[test]
    #[should_panic]
    fn p384_redox_err_ser() {
        // trigger error if buffer is malformed
        let pog = PrimeOrderGroup::p384();
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
    fn p384_redox_point_mult() {
        let pog = PrimeOrderGroup::p384();
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
    fn p384_redox_encode_to_group() {
        let pog = PrimeOrderGroup::p384();
        let buf: [u8; 32] = [0; 32];
        let p = (pog.encode_to_group)(&buf);
        let mut ser: Vec<u8> = Vec::new();
        (pog.serialize)(&p, true, &mut ser);
        // TODO: use official test vector
        let test_arr: [u8; 1+P384_BYTE_LENGTH] = [
            3, 71, 200, 194, 66, 217, 162, 108, 160, 125, 77, 19, 159, 198, 168,
            53, 78, 216, 108, 129, 84, 67, 119, 32, 221, 107, 28, 72, 61, 140,
            154, 6, 34, 23, 98, 185, 185, 126, 14, 208, 77, 63, 13, 237, 235,
            166, 220, 134, 81
        ];
        assert_eq!(ser, test_arr.to_vec())
    }

    #[test]
    fn p384_redox_rand_bytes() {
        let pog = PrimeOrderGroup::p384();
        let mut r: Vec<u8> = Vec::new();
        (pog.uniform_bytes)(&mut r);
        assert_eq!(r.len(), pog.byte_length);
        let fixed = p384_redox_convert_slice_to_fixed(&r);
        assert_eq!(fixed.len(), pog.byte_length);
        for i in 0..pog.byte_length {
            assert_eq!(r[i], fixed[i]);
        }
    }

    #[test]
    fn p384_redox_inverse_mult() {
        let pog = PrimeOrderGroup::p384();
        let mut r: Vec<u8> = Vec::new();
        (pog.uniform_bytes)(&mut r);
        let p = (pog.random_element)();
        let r_p = (pog.scalar_mult)(&p, &r);
        let inv_r_p = (pog.inverse_mult)(&r_p, &r);
        assert!(inv_r_p.equals(&p));
    }

    #[test]
    fn p384_redox_dleq() {
        let pog = PrimeOrderGroup::p384();

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
    fn p384_redox_batch_dleq() {
        let pog = PrimeOrderGroup::p384();

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
    fn p384_redox_dleq_fail() {
        let pog = PrimeOrderGroup::p384();

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
    fn p384_redox_batch_dleq_fail_bad_batch() {
        let pog = PrimeOrderGroup::p384();

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
    fn p384_redox_convert_slice_to_fixed(x: &[u8]) -> [u8; P384_BYTE_LENGTH] {
        let mut inp_bytes = [0; P384_BYTE_LENGTH];
        let random_bytes = &x[..inp_bytes.len()];
        inp_bytes.copy_from_slice(random_bytes);
        inp_bytes
    }
}