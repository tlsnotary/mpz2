use std::collections::HashMap;

use crate::{Circuit, CircuitBuilder, components::GateType};
use regex::{Captures, Regex};

static HEADER_PATTERN: &str = r"(?m)^(?P<gate_count>\d+)\s+(?P<wire_count>\d+)\s*\n(?P<input_line>\d+(?:\s+\d+)*)\s*\n(?P<output_line>\d+(?:\s+\d+)*)\s*$";
static GATE_PATTERN: &str = r"(?P<input_count>\d+)\s(?P<output_count>\d+)\s(?P<xref>\d+)\s(?:(?P<yref>\d+)\s)?(?P<zref>\d+)\s(?P<gate>INV|AND|XOR)";

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error("invalid header")]
    InvalidHeader,
    #[error(transparent)]
    ParseIntError(#[from] std::num::ParseIntError),
    #[error("uninitialized feed: {0}")]
    UninitializedFeed(usize),
    #[error("unsupported gate type: {0}")]
    UnsupportedGateType(String),
    #[error(transparent)]
    BuilderError(#[from] crate::BuilderError),
}

impl Circuit {
    /// Parses a circuit in Bristol-fashion format from a string.
    ///
    /// See `https://nigelsmart.github.io/MPC-Circuits/` for more information.
    ///
    /// # Arguments
    ///
    /// * `circuit_str` - The string containing the circuit description.
    ///
    /// # Returns
    ///
    /// The parsed circuit.
    pub fn parse_str(circuit_str: &str) -> Result<Self, ParseError> {
        let mut builder = CircuitBuilder::new();

        let header_pattern = Regex::new(HEADER_PATTERN).unwrap();
        let Some(header_captures) = header_pattern.captures(circuit_str) else {
            return Err(ParseError::InvalidHeader);
        };

        let gate_count: usize = header_captures
            .name("gate_count")
            .unwrap()
            .as_str()
            .parse()?;

        let input_lengths = header_captures
            .name("input_line")
            .unwrap()
            .as_str()
            .split_whitespace()
            .skip(1) // skip the count
            .map(|s| s.parse::<usize>().map_err(ParseError::ParseIntError))
            .collect::<Result<Vec<_>, _>>()?;

        let output_lengths = header_captures
            .name("output_line")
            .unwrap()
            .as_str()
            .split_whitespace()
            .skip(1) // skip the count
            .map(|s| s.parse::<usize>().map_err(ParseError::ParseIntError))
            .collect::<Result<Vec<_>, _>>()?;

        let feed_count = input_lengths.iter().sum::<usize>() + gate_count;
        let mut feed_map = HashMap::with_capacity(feed_count);

        for i in 0..input_lengths.iter().sum::<usize>() {
            feed_map.insert(i, builder.add_input());
        }

        let pattern = Regex::new(GATE_PATTERN).unwrap();
        for cap in pattern.captures_iter(circuit_str) {
            let UncheckedGate {
                xref,
                yref,
                zref,
                gate_type,
            } = UncheckedGate::parse(cap)?;

            match gate_type {
                GateType::Xor => {
                    let new_x = feed_map
                        .get(&xref)
                        .ok_or(ParseError::UninitializedFeed(xref))?;
                    let new_y = feed_map
                        .get(&yref.unwrap())
                        .ok_or(ParseError::UninitializedFeed(yref.unwrap()))?;
                    let z = builder.add_xor_gate(*new_x, *new_y);
                    feed_map.insert(zref, z);
                }
                GateType::And => {
                    let new_x = feed_map
                        .get(&xref)
                        .ok_or(ParseError::UninitializedFeed(xref))?;
                    let new_y = feed_map
                        .get(&yref.unwrap())
                        .ok_or(ParseError::UninitializedFeed(yref.unwrap()))?;
                    let new_z = builder.add_and_gate(*new_x, *new_y);
                    feed_map.insert(zref, new_z);
                }
                GateType::Inv => {
                    let new_x = feed_map
                        .get(&xref)
                        .ok_or(ParseError::UninitializedFeed(xref))?;
                    let new_z = builder.add_inv_gate(*new_x);
                    feed_map.insert(zref, new_z);
                }
                GateType::Id => {
                    let new_x = feed_map
                        .get(&xref)
                        .ok_or(ParseError::UninitializedFeed(xref))?;
                    let new_z = builder.add_id_gate(*new_x);
                    feed_map.insert(zref, new_z);
                }
            }
        }

        for i in (feed_count - output_lengths.iter().sum::<usize>())..feed_count {
            builder.add_output(*feed_map.get(&i).unwrap());
        }

        Ok(builder.build()?)
    }

    /// Parses a circuit in Bristol-fashion format from a file.
    ///
    /// See `https://nigelsmart.github.io/MPC-Circuits/` for more information.
    ///
    /// # Arguments
    ///
    /// * `filename` - Path to the file containing the circuit description.
    ///
    /// # Returns
    ///
    /// The parsed circuit.
    pub fn parse(filename: &str) -> Result<Self, ParseError> {
        let file = std::fs::read_to_string(filename)?;
        Self::parse_str(&file)
    }
}

struct UncheckedGate {
    xref: usize,
    yref: Option<usize>,
    zref: usize,
    gate_type: GateType,
}

impl UncheckedGate {
    fn parse(captures: Captures) -> Result<Self, ParseError> {
        let xref: usize = captures.name("xref").unwrap().as_str().parse()?;
        let yref: Option<usize> = captures
            .name("yref")
            .map(|yref| yref.as_str().parse())
            .transpose()?;
        let zref: usize = captures.name("zref").unwrap().as_str().parse()?;
        let gate_type = captures.name("gate").unwrap().as_str();

        let gate_type = match gate_type {
            "XOR" => GateType::Xor,
            "AND" => GateType::And,
            "INV" => GateType::Inv,
            _ => return Err(ParseError::UnsupportedGateType(gate_type.to_string())),
        };

        Ok(Self {
            xref,
            yref,
            zref,
            gate_type,
        })
    }
}

#[cfg(test)]
mod tests {
    use itybity::{FromBitIterator, ToBits};

    use super::*;

    #[test]
    fn test_parse_adder_64() {
        let circ = Circuit::parse("bristol/adder64_reverse.txt").unwrap();
        let (a, b) = (59u64, 101312320u64);
        let output =
            u64::from_lsb0_iter(circ.evaluate(a.iter_lsb0().chain(b.iter_lsb0())).unwrap());
        assert_eq!(output, a + b);
    }

    #[test]
    #[ignore = "expensive"]
    fn test_parse_aes() {
        use aes::{
            Aes128,
            cipher::{BlockCipherEncrypt, KeyInit},
        };

        use rand::{RngExt, SeedableRng, rngs::StdRng};
        let mut rng = StdRng::seed_from_u64(0);

        let key: [u8; 16] = rng.random();
        let msg: [u8; 16] = rng.random();

        let circ = Circuit::parse("bristol/aes_128_reverse.txt").unwrap();

        let ciphertext = <[u8; 16]>::from_lsb0_iter(
            circ.evaluate(key.iter_lsb0().chain(msg.iter_lsb0()))
                .unwrap(),
        );

        let aes = Aes128::new_from_slice(&key).unwrap();
        let mut expected = msg.into();
        aes.encrypt_block(&mut expected);
        let expected: [u8; 16] = expected.into();

        assert_eq!(ciphertext, expected);
    }

    #[test]
    #[ignore = "expensive"]
    fn test_parse_sha() {
        use sha2::block_api::compress256;

        let circ = Circuit::parse("bristol/sha256_reverse.txt").unwrap();

        static SHA2_INITIAL_STATE: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];

        let msg = [69u8; 64];

        let output = <[u32; 8]>::from_lsb0_iter(
            circ.evaluate(msg.iter_lsb0().chain(SHA2_INITIAL_STATE.iter_lsb0()))
                .unwrap(),
        );

        let mut expected = SHA2_INITIAL_STATE;
        compress256(&mut expected, &[msg]);

        assert_eq!(output, expected);
    }
}
