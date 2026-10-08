//! Pre-built circuits for MPC.
#![allow(unused_imports)]
use mpz_circuits_core::Circuit;
use once_cell::sync::Lazy;
use std::sync::Arc;

/// AES-128 circuit.
///
/// The circuit has the following signature:
///
/// `fn(key: [u8; 16], msg: [u8; 16]) -> [u8; 16]`
#[cfg(feature = "aes")]
pub static AES128: Lazy<Arc<Circuit>> = Lazy::new(|| {
    let bytes = include_bytes!("../data/aes_128.bin");
    Arc::new(bincode::deserialize(bytes).unwrap())
});

/// AES-128 key schedule circuit.
///
/// The circuit has the following signature:
///
/// `fn(key: [u8; 16]) -> [u8; 176]`
///
/// The output is the key schedule: 11 round keys, 16 bytes each.
#[cfg(feature = "aes")]
pub static AES128_KS: Lazy<Arc<Circuit>> = Lazy::new(|| {
    let bytes = include_bytes!("../data/aes_128_ks.bin");
    Arc::new(bincode::deserialize(bytes).unwrap())
});

/// AES-128 post key schedule encryption circuit.
///
/// The circuit has the following signature:
///
/// `fn(key_schedule: [u8; 176], msg: [u8; 16]) -> [u8; 16]`
///
/// `key_schedule` is 11 round keys, 16 bytes each.
#[cfg(feature = "aes")]
pub static AES128_POST_KS: Lazy<Arc<Circuit>> = Lazy::new(|| {
    let bytes = include_bytes!("../data/aes_128_post_ks.bin");
    Arc::new(bincode::deserialize(bytes).unwrap())
});

/// SHA-256 circuit.
///
/// The circuit has the following signature:
///
/// `fn(msg: [u8; 64], state: [u32; 8]) -> [u32; 8]`
#[cfg(feature = "sha2")]
pub static SHA256_COMPRESS: Lazy<Arc<Circuit>> = Lazy::new(|| {
    let bytes = include_bytes!("../data/sha256.bin");
    Arc::new(bincode::deserialize(bytes).unwrap())
});

/// Blake3 compression circuit.
///
/// The circuit has the following signature:
///
/// `fn(msg: [u32; 16], state: [u32; 16]) -> [u32; 16]`
#[cfg(feature = "blake3")]
pub static BLAKE3_COMPRESS: Lazy<Arc<Circuit>> = Lazy::new(|| {
    let bytes = include_bytes!("../data/blake3.bin");
    Arc::new(bincode::deserialize(bytes).unwrap())
});

/// Keccak-f[1600] permutation circuit.
///
/// The circuit has the following signature:
///
/// `fn(state: [u64; 25]) -> [u64; 25]`
#[cfg(feature = "keccak")]
pub static KECCAK_PERMUTE: Lazy<Arc<Circuit>> = Lazy::new(|| {
    let bytes = include_bytes!("../data/keccak_f.bin");
    Arc::new(bincode::deserialize(bytes).unwrap())
});

#[cfg(test)]
mod tests {
    use super::*;
    use mpz_circuits_core::evaluate;

    #[test]
    #[cfg(feature = "aes")]
    fn test_aes128() {
        use aes::cipher::{BlockCipherEncrypt, KeyInit};
        use rand::{RngExt, SeedableRng, rngs::StdRng};

        fn aes_128(key: [u8; 16], msg: [u8; 16]) -> [u8; 16] {
            use aes::Aes128;

            let aes = Aes128::new_from_slice(&key).unwrap();
            let mut ciphertext = msg.into();
            aes.encrypt_block(&mut ciphertext);
            ciphertext.into()
        }

        let mut rng = StdRng::seed_from_u64(0);

        let key: [u8; 16] = rng.random();
        let msg: [u8; 16] = rng.random();
        let ciphertext: [u8; 16] = evaluate!(AES128, key, msg).unwrap();
        let expected = aes_128(key, msg);
        assert_eq!(ciphertext, expected);
    }

    #[test]
    #[cfg(feature = "aes")]
    #[ignore = "expensive"]
    fn test_parse_aes_key_schedule() {
        let (key, expected_ks, _, _) = aes_vectors();
        let ks: [u8; 176] = evaluate!(AES128_KS, key).unwrap();
        assert_eq!(expected_ks, ks);
    }

    #[test]
    #[cfg(feature = "aes")]
    #[ignore = "expensive"]
    fn test_parse_aes_post_key_schedule() {
        let (_, ks, msg, expected_out) = aes_vectors();
        let output: [u8; 16] = evaluate!(AES128_POST_KS, ks, msg).unwrap();
        assert_eq!(expected_out, output);
    }

    #[test]
    #[cfg(feature = "sha2")]
    fn test_sha256_compress() {
        static SHA2_INITIAL_STATE: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];

        fn sha256_compress(msg: [u8; 64], state: [u32; 8]) -> [u32; 8] {
            let mut state = state;
            sha2::block_api::compress256(&mut state, &[msg]);
            state
        }

        let msg = [69u8; 64];
        let output: [u32; 8] = evaluate!(SHA256_COMPRESS, msg, SHA2_INITIAL_STATE).unwrap();
        let expected = sha256_compress(msg, SHA2_INITIAL_STATE);
        assert_eq!(output, expected);
    }

    #[test]
    #[cfg(feature = "blake3")]
    fn test_blake3() {
        let iv = [1u32; 16];
        let msg = [1u32; 16];
        // Output obtained from `test_blake3_compress`
        // in crates/circuits-core/src/circuits/blake3.rs
        let expected_output: [u32; 16] = [
            3007729955, 3007729955, 3007729955, 3007729955, 34758502, 34758502, 34758502, 34758502,
            4028310545, 4028310545, 4028310545, 4028310545, 2799904522, 2799904522, 2799904522,
            2799904522,
        ];

        let output: [u32; 16] = evaluate!(BLAKE3_COMPRESS, msg, iv).unwrap();

        assert_eq!(output, expected_output);
    }

    #[test]
    #[cfg(feature = "keccak")]
    fn test_keccak_permute() {
        let mut init_state: [u64; 25] = [1u64; 25].map(u64::to_le);

        let output: [u64; 25] = evaluate!(KECCAK_PERMUTE, init_state).unwrap();

        // Puts expected output into `init_state`.
        keccak::Keccak::new().with_f1600(|f| f(&mut init_state));

        assert_eq!(output, init_state);
    }

    // Test vectors from https://csrc.nist.gov/files/pubs/fips/197/final/docs/fips-197.pdf
    // Returns a tuple (key, key schedule, input, output).
    #[allow(dead_code)]
    fn aes_vectors() -> ([u8; 16], [u8; 176], [u8; 16], [u8; 16]) {
        use zerocopy::IntoBytes;

        #[rustfmt::skip]
        const AES128_KEY_U32: [u32; 4] = [
            0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c,
        ];
        #[rustfmt::skip]
        const AES128_ROUND_KEYS_U32: [u32; 44] = [
            0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c,
            0xa0fafe17, 0x88542cb1, 0x23a33939, 0x2a6c7605,
            0xf2c295f2, 0x7a96b943, 0x5935807a, 0x7359f67f,
            0x3d80477d, 0x4716fe3e, 0x1e237e44, 0x6d7a883b,
            0xef44a541, 0xa8525b7f, 0xb671253b, 0xdb0bad00,
            0xd4d1c6f8, 0x7c839d87, 0xcaf2b8bc, 0x11f915bc,
            0x6d88a37a, 0x110b3efd, 0xdbf98641, 0xca0093fd,
            0x4e54f70e, 0x5f5fc9f3, 0x84a64fb2, 0x4ea6dc4f,
            0xead27321, 0xb58dbad2, 0x312bf560, 0x7f8d292f,
            0xac7766f3, 0x19fadc21, 0x28d12941, 0x575c006e,
            0xd014f9a8, 0xc9ee2589, 0xe13f0cc8, 0xb6630ca6,
        ];
        const INPUT: u128 = 0x32_43_f6_a8_88_5a_30_8d_31_31_98_a2_e0_37_07_34;
        const OUTPUT: u128 = 0x39_25_84_1d_02_dc_09_fb_dc_11_85_97_19_6a_0b_32;

        let key: [u32; 4] = AES128_KEY_U32.map(u32::to_be);
        let ks: [u32; 44] = AES128_ROUND_KEYS_U32.map(u32::to_be);
        let inp = INPUT.to_be();
        let out = OUTPUT.to_be();

        (
            key.as_bytes().try_into().unwrap(),
            ks.as_bytes().try_into().unwrap(),
            inp.as_bytes().try_into().unwrap(),
            out.as_bytes().try_into().unwrap(),
        )
    }
}
