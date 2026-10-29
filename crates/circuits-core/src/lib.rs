//! This crate provides types for representing computation as binary circuits.
#![deny(missing_docs, unreachable_pub, unused_must_use)]

#[cfg(not(target_endian = "little"))]
compile_error!("mpz requires a little-endian target; big-endian hosts are not supported");

extern crate self as mpz_circuits;

mod builder;
mod circuit;
pub mod circuits;
pub(crate) mod components;
pub mod ops;
#[cfg(feature = "parse")]
mod parse;

pub use builder::{BuilderError, CircuitBuilder};
pub use circuit::{Circuit, CircuitError};
#[doc(hidden)]
pub use components::{Feed, Node, Sink};
pub use components::{Gate, GateType};

#[doc(hidden)]
pub use itybity;
pub use once_cell;

/// Evaluate a circuit with the given arguments.
///
/// # Example
///
/// ```rust
/// use mpz_circuits_core::*;
///
/// let circ = circuits::adder_u8();
/// let a = 42u8;
/// let b = 69u8;
///
/// let sum: u8 = evaluate!(circ, a, b).unwrap();
///
/// assert_eq!(sum, a + b);
/// ```
#[macro_export]
macro_rules! evaluate {
    ($circuit:expr, $($arg:expr),+ $(,)?) => {{
        use $crate::itybity::{ToBits, FromBitIterator};
        let input = std::iter::empty()
            $(.chain($arg.iter_lsb0()))*;
        $circuit.evaluate(input).map(|output| FromBitIterator::from_lsb0_iter(output))
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evaluate_macro() {
        let circ = circuits::adder_u8();

        let a = 42u8;
        let b = 69u8;

        let sum: u8 = evaluate!(circ, a, b).unwrap();

        assert_eq!(sum, a + b);
    }
}
