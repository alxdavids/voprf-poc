//! The macros module contains the functionality required by the
//! prime-order group instantiation based on redox_ecc.

/// serializes point objects from redox_ecc crate into byte arrays
///
/// # Function signature
///
/// `fn point_serialize(p: &Point, compress: bool, out: &mut Vec<u8>)`
///
/// where `Point` implements `redox_ecc::ellipticcurve::EcPoint`
#[macro_export]
macro_rules! point_serialize {
    ($p:expr, $compress:expr, $out:expr) => {{
        let p_clone = $p.clone();
        let bytes = p_clone.encode($compress);
        copy_into(&bytes, $out);
    }}
}

/// returns the number of bytes used to express field elements
/// associated with the curve
///
/// # Function signature
///
/// `fn field_byte_length(curve: &Curve) -> usize`
///
/// where `Curve` implements `redox_ecc::ellipticcurve::EllipticCurve`
#[macro_export]
macro_rules! field_byte_length {
    ($curve:expr) => {
        ($curve.get_field().get_modulus().bits()+7)/8
    }
}

/// returns the number of bytes used to express scalars associated with
/// the curve
///
/// # Function signature
///
/// `fn scalar_byte_length(curve: &Curve) -> usize`
///
/// where `Curve` implements `redox_ecc::ellipticcurve::EllipticCurve`
#[macro_export]
macro_rules! scalar_byte_length {
    ($curve:expr) => {
        ($curve.get_order().bits()+7)/8
    }
}

/// hashes bytes to a curve
///
/// # Function signature
///
/// `fn hash_to_curve(suite: h2c_rust_ref::Suite<T>, buf: &[u8], dst: &[u8]) -> Point`
#[macro_export]
macro_rules! hash_to_curve {
    ($suite:expr, $buf:expr, $dst:expr) => {{
        let h = $suite.get($dst);
        let mut p = h.hash($buf);
        p.normalize();
        p
    }}
}

/// generates a DLEQ proof object for Point objects
///
/// # Function signature
///
/// `fn dleq_gen(curve: &Curve, key: &[u8], pub_key: &Point, input: &Point, eval: &Point) -> [Vec<u8>; 2]`
#[macro_export]
macro_rules! dleq_gen {
    ($curve:expr, $key:expr, $pub_key:expr, $input:expr, $eval:expr) => {{
        let mut t: Vec<u8> = Vec::new();
        fill_uniform_bytes!($curve, &mut t);
        fixed_dleq_gen!($curve, $key, $pub_key, $input, $eval, &t)
    }}
}

/// generates a DLEQ proof object for Point objects with fixed
/// scalar input
///
/// # Function signature
///
/// `fn fixed_dleq_gen(curve: &Curve, key: &[u8], pub_key: &Point, input: &Point, eval: &Point, t: &[u8]) -> [Vec<u8>; 2]`
#[macro_export]
macro_rules! fixed_dleq_gen {
    ($curve:expr, $key:expr, $pub_key:expr, $input:expr, $eval:expr, $t:expr) => {{
        let gen = $curve.get_generator();
        let t_sc = to_scalar!($curve, $t);
        let a = &gen * &t_sc;
        let b = $input * &t_sc;
        let mut c = vec![0; scalar_byte_length!($curve)];
        compute_expanded_dleq_challenge!($curve, &[$pub_key, $input, $eval, &a, &b], &mut c);
        let c_sc = to_scalar!($curve, &c);
        let k_sc = to_scalar!($curve, $key);
        let s_sc = t_sc - (c_sc * k_sc);
        [c, s_sc.to_bytes_be()]
    }}
}

/// converts a u8 value into a redox scalar for internal operations
///
/// # Function signature
///
/// `fn to_scalar(curve: &Curve, val: &[u8]) -> Scalar`
#[macro_export]
macro_rules! to_scalar {
    ($curve:expr, $val:expr) => {
        $curve.new_scalar(BigInt::from_bytes_be(Sign::Plus, $val))
    }
}

/// Samples the random challenge value `c` used in the NI version of the
/// DLEQ proof system
///
/// # Function signature
///
/// `fn compute_expanded_dleq_challenge(curve: &Curve, inputs: &[&WPoint], c: &mut Vec<u8>)`
#[macro_export]
macro_rules! compute_expanded_dleq_challenge {
    ($curve:expr, $inputs:expr, $c:expr) => {{
        let mut seed: Vec<u8> = Vec::new();
        dleq_hash!($curve, $inputs, &mut seed);
        let label = "voprf_dleq_challenge".as_bytes();
        let mut ctr = 0;
        loop {
            compute_masked_expansion!($curve, &seed, label, ctr, $c);
            if !(verify_scalar_size!($curve, $c)) {
                ctr = ctr+1;
                continue;
            }
            break;
        }
    }}
}

/// hash inputs points for DLEQ proofs into the output buffer `out`
///
/// # Function signature
///
/// `fn dleq_hash(curve: &Curve, to_hash: &[&Point], out: &mut Vec<u8>)`
#[macro_export]
macro_rules! dleq_hash {
    ($curve:expr, $to_hash:expr, $out:expr) => {{
        let mut hash = hash!();
        let mut ser: Vec<u8> = Vec::new();
        point_serialize!($curve.get_generator(), true, &mut ser);
        hash.input(&ser);
        for p in $to_hash {
            point_serialize!(&p, true, &mut ser);
            hash.input(&ser);
        }
        copy_into(&hash.result(), $out);
    }}
}

/// this functions computes a scalar where excess bits are masked off.
/// This is necessary if the size of the underlying field is not a whole
/// number of bytes (such as for P-521).
///
/// # Function signature
///
/// `fn compute_masked_expansion(curve: &Curve, seed: &[u8], label: &[u8], ctr: u32, c: &mut Vec<u8>)`
#[macro_export]
macro_rules! compute_masked_expansion {
    ($curve:expr, $seed:expr, $label:expr, $ctr:expr, $c:expr) => {{
        let mut info = Vec::new();
        info.write_u32::<BigEndian>($ctr as u32).unwrap();
        info.extend_from_slice($label);
        Hkdf{}.expand($seed, &info, $c);
        mask_scalar!($curve, $c);
    }}
}

/// Fills the input slice with random bytes up to the input length
///
/// # Function signature
///
/// `fn fill_uniform_bytes(curve: &Curve, out: &mut Vec<u8>)`
#[macro_export]
macro_rules! fill_uniform_bytes {
    ($curve:expr, $out:expr) => {{
        let mut rng = OsRng;
        let mut alpha = vec![0; scalar_byte_length!($curve)];
        rng.fill_bytes(&mut alpha);
        copy_into(&alpha, $out);
    }}
}

/// Masks a scalar according to the size of the curve's modulus
///
/// # Function signature
///
/// `fn mask_scalar(curve: &Curve, scalar: &mut Vec<u8>)`
#[macro_export]
macro_rules! mask_scalar {
    ($curve:expr, $scalar:expr) => {{
        let bit_size = $curve.get_order().bits();
        $scalar[0] = $scalar[0] & CURVE_BITMASK[bit_size % 8];
    }}
}

/// returns true if the scalar is within the order of the base field, and
/// false otherwise.
///
/// # Function signature
///
/// `fn verify_scalar_size(curve: &Curve, c: &[u8]) -> bool`
#[macro_export]
macro_rules! verify_scalar_size {
    ($curve:expr, $c:expr) => {{
        let modulus = $curve.get_order();
        BigUint::from_bytes_be($c) < modulus
    }}
}

/// returns the associated hash function (SHA512) for working with the
/// prime-order group
///
/// # Function signature
///
/// `fn hash() -> Sha512`
#[macro_export]
macro_rules! hash {
    () => {
        Sha512::new()
    }
}

/// verifies the provided DLEQ proof
///
/// # Function signature
///
/// `fn dleq_vrf(curve: &Curve, pub_key: &WPoint, input: &WPoint, eval: &WPoint, proof: &[Vec<u8>; 2]) -> bool`
#[macro_export]
macro_rules! dleq_vrf {
    ($curve:expr, $pub_key:expr, $input:expr, $eval:expr, $proof:expr) => {{
        let gen = $curve.get_generator();
        let c_proof = &$proof[0];
        let s_proof = &$proof[1];
        let c_sc = to_scalar!($curve, c_proof);
        let s_sc = to_scalar!($curve, s_proof);
        let s_g = &gen * &s_sc;
        let c_pk = $pub_key * &c_sc;
        let a = s_g + c_pk;
        let s_m = $input * &s_sc;
        let c_z = $eval * &c_sc;
        let b = s_m + c_z;
        let mut c_vrf = vec![0; field_byte_length!($curve)];
        compute_expanded_dleq_challenge!($curve, &[$pub_key, $input, $eval, &a, &b], &mut c_vrf);
        c_proof == &c_vrf
    }}
}

/// computes composite scalars for batched proof generation/verification
///
/// # Function signature
///
/// `fn batch_compute_composities(curve: &Curve, pub_key: &Point, inputs: &[Point], evals: &[Point]) -> [Point; 2]`
#[macro_export]
macro_rules! batch_compute_composities {
    ($curve:expr, $pub_key:expr, $inputs:expr, $evals:expr) => {{
        assert_eq!($inputs.len(), $evals.len());
        let mut seed: Vec<u8> = Vec::new();
        batch_dleq_seed!($curve, $pub_key, $inputs, $evals, &mut seed);
        compute_composites!($curve, &seed, $inputs, $evals)
    }}
}

/// computes composite curve points that are used in batch DLEQ
///
/// # Function signature
///
/// `fn compute_composites(curve: &Curve, seed: &[u8], inputs: &[WPoint], evals: &[WPoint]) -> [WPoint; 2]`
#[macro_export]
macro_rules! compute_composites {
    ($curve:expr, $seed:expr, $inputs:expr, $evals:expr) => {{
        // init these with dummy values
        let mut comp_m = $curve.get_generator(); // dummy point
        let mut comp_z = $curve.get_generator(); // dummy point
        let label = "voprf_batch_dleq".as_bytes();
        let mut ctr = 0; // used for labelling hkdf implementation
        let mut i = 0; // counts the number of items to process
        while i < $inputs.len() {
            let m_i = &$inputs[i];
            let z_i = &$evals[i];

            // sample coefficient
            let mut d_i = vec![0; field_byte_length!($curve)];
            compute_masked_expansion!($curve, $seed, &label, ctr, &mut d_i);
            ctr = ctr + 1;
            // reject if greater than N
            if !verify_scalar_size!($curve, &d_i) {
                println!("rejected scalar");
                continue;
            }
            let d_i_sc = to_scalar!($curve, &d_i);
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
    }}
}

/// generates a seed for deriving coefficients that are used to construct
/// the composite point objects used in batch DLEQ proofs, moves the
/// result into the provided output buffer
///
/// # Function signature
///
/// `fn batch_dleq_seed(curve: &Curve, y: &Point, m: &[Point], z: &[Point], out: &mut Vec<u8>)`
#[macro_export]
macro_rules! batch_dleq_seed {
    ($curve:expr, $y:expr, $m:expr, $z:expr, $out:expr) => {{
        let mut inputs = Vec::new();
        inputs.push($y);
        inputs.extend($m);
        inputs.extend($z);
        dleq_hash!($curve, &inputs, $out)
    }}
}
