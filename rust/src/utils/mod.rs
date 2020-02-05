//! The `utils` module provides access to a small number of utility functions
//! for processing data.

use byteorder::{LittleEndian, WriteBytesExt};
use rand_core::{RngCore, OsRng};

/// Moves a user-specified number of uniformly sampled bytes into the provided
/// output buffer
///
/// # Arguments
///
/// * `byte_length`: a `usize` parameter specifying the number of bytes to
///   output
/// * `out`: the output buffer where the bytes will be stored
///
/// # Examples
///
/// ```
/// use voprf_rs::utils::rand_bytes;
/// let mut out: Vec<u8> = Vec::new();
/// let byte_length: usize = 32;
/// rand_bytes(byte_length, &mut out);
/// ```
pub fn rand_bytes(byte_length: usize, out: &mut Vec<u8>) {
    let mut rng = OsRng;
    let mut concat: Vec<u8> = Vec::new();
    while concat.len() < byte_length {
        let u = rng.next_u32();
        let mut vec = Vec::new();
        vec.write_u32::<LittleEndian>(u).unwrap();
        let mut ctr = 0;
        while concat.len() < byte_length && ctr < 4 {
            concat.push(vec[ctr]);
            ctr = ctr+1;
        }
    }
    copy_into(&concat, out)
}

/// Moves the contents of `src` into the provided output buffer `dst`. Clears
/// the contents of `dst` first.
pub fn copy_into(src: &[u8], dst: &mut Vec<u8>) {
    dst.clear();
    dst.extend_from_slice(src)
}