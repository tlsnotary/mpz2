#![cfg_attr(feature = "simd-transpose", feature(portable_simd))]

#[cfg(feature = "simd-transpose")]
#[cfg(target_arch = "x86_64")]
pub const LANE_COUNT: usize = 32;

#[cfg(feature = "simd-transpose")]
#[cfg(target_arch = "wasm32")]
pub const LANE_COUNT: usize = 16;

#[cfg(not(feature = "simd-transpose"))]
pub const LANE_COUNT: usize = 8;

#[cfg(not(feature = "simd-transpose"))]
mod scalar;
#[cfg(feature = "simd-transpose")]
mod simd;

#[cfg(feature = "simd-transpose")]
pub use simd::transpose_unchecked;

#[cfg(not(feature = "simd-transpose"))]
pub use scalar::transpose_unchecked;

use thiserror::Error;

/// This function transposes a matrix on the bit-level.
///
/// Assumes an LSB0 bit encoding of the matrix.
/// This implementation requires that the number of rows is a power of 2
/// and that the number of columns is a multiple of 8
pub fn transpose_bits(matrix: &mut [u8], rows: usize) -> Result<(), TransposeError> {
    // Check that number of rows is a power of 2
    if rows & (rows - 1) != 0 {
        return Err(TransposeError::InvalidNumberOfRows);
    }

    // Check that slice is rectangular i.e. the number of cells is a multiple of
    // the number of rows
    if matrix.len() & (rows - 1) != 0 {
        return Err(TransposeError::MalformedSlice);
    }

    // Check that columns is a multiple of 8
    let columns = matrix.len() / rows;
    if columns & 7 != 0 || columns < 8 {
        return Err(TransposeError::InvalidNumberOfColumns);
    }

    #[cfg(feature = "simd-transpose")]
    simd::transpose_bits(matrix, rows)?;
    #[cfg(not(feature = "simd-transpose"))]
    unsafe {
        scalar::transpose_unchecked(matrix, rows.trailing_zeros() as usize);
        scalar::bitmask_shift(matrix, rows);
    }
    Ok(())
}

#[derive(Error, Debug, PartialEq)]
pub enum TransposeError {
    #[error("Number of rows is not a power of 2")]
    InvalidNumberOfRows,
    #[error("Provided slice is not of rectangular shape")]
    MalformedSlice,
    #[error("Number of columns must be a multiple of lane count")]
    InvalidNumberOfColumns,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{distr::StandardUniform, prelude::*};

    fn random_vec<T>(elements: usize) -> Vec<T>
    where
        StandardUniform: Distribution<T>,
    {
        let mut rng = rand::rng();
        (0..elements).map(|_| rng.random::<T>()).collect()
    }

    fn transpose_naive(data: &[u8], row_width: usize) -> Vec<u8> {
        use itybity::*;

        let bits: Vec<Vec<bool>> = data.chunks(row_width).map(|x| x.to_lsb0_vec()).collect();
        let col_count = bits[0].len();
        let row_count = bits.len();

        let mut bits_: Vec<Vec<bool>> = vec![vec![false; row_count]; col_count];

        #[allow(clippy::needless_range_loop)]
        for j in 0..row_count {
            #[allow(clippy::needless_range_loop)]
            for i in 0..col_count {
                bits_[i][j] = bits[j][i];
            }
        }

        bits_
            .into_iter()
            .flat_map(Vec::<u8>::from_lsb0_iter)
            .collect()
    }

    #[test]
    fn test_transpose_bits() {
        let rows = 64;
        let columns = 32;

        let mut matrix: Vec<u8> = random_vec::<u8>(columns * rows);
        let naive = transpose_naive(&matrix, columns);

        transpose_bits(&mut matrix, rows).unwrap();

        assert_eq!(naive, matrix);
    }

    #[test]
    fn test_transpose_naive() {
        let matrix = [
            // ------- bits in lsb0
            3u8,   // 1 1 0 0 0 0 0 0
            76u8,  // 0 0 1 1 0 0 1 0
            120u8, // 0 0 0 1 1 1 1 0
            9u8,   // 1 0 0 1 0 0 0 0
            17u8,  // 1 0 0 0 1 0 0 0
            102u8, // 0 1 1 0 0 1 1 0
            53u8,  // 1 0 1 0 1 1 0 0
            125u8, // 1 0 1 1 1 1 1 0
        ];

        let expected = [
            // ------- bits in lsb0
            217u8, // 1 0 0 1 1 0 1 1
            33u8,  // 1 0 0 0 0 1 0 0
            226u8, // 0 1 0 0 0 1 1 1
            142u8, // 0 1 1 1 0 0 0 1
            212u8, // 0 0 1 0 1 0 1 1
            228u8, // 0 0 1 0 0 1 1 1
            166u8, // 0 1 1 0 0 1 0 1
            0u8,   // 0 0 0 0 0 0 0 0
        ];

        let naive = transpose_naive(&matrix, 1);

        assert_eq!(naive, expected);
    }

    #[test]
    fn test_transpose() {
        let rounds = 6_u32;
        let mut rows = 2_usize.pow(rounds);
        let mut columns = 32;

        let mut matrix: Vec<u8> = random_vec::<u8>(columns * rows);
        let original = matrix.clone();
        unsafe {
            #[cfg(feature = "simd-transpose")]
            simd::transpose_unchecked::<32, u8>(&mut matrix, rounds as usize);
            #[cfg(not(feature = "simd-transpose"))]
            scalar::transpose_unchecked::<u8>(&mut matrix, rounds as usize);
        }

        (rows, columns) = (columns, rows);
        for (k, element) in matrix.iter().enumerate() {
            let row_number = k / columns;
            let column_number = k % columns;
            assert_eq!(*element, original[column_number * rows + row_number])
        }
    }

    #[test]
    fn test_bitmask_shift() {
        let columns = 32;
        let rows = 64;

        let mut matrix: Vec<u8> = random_vec::<u8>(columns * rows);
        let mut original = matrix.clone();
        #[cfg(feature = "simd-transpose")]
        unsafe {
            simd::bitmask_shift_unchecked(&mut matrix, columns);
        }
        #[cfg(not(feature = "simd-transpose"))]
        scalar::bitmask_shift(&mut matrix, columns);

        for (row_index, row) in original.chunks_mut(columns).enumerate() {
            for k in 0..8 {
                for (l, chunk) in row.chunks(8).enumerate() {
                    let expected: u8 = chunk.iter().enumerate().fold(0, |acc, (m, element)| {
                        acc + (element & 1) * 2_u8.pow(m as u32)
                    });
                    let actual = matrix[row_index * columns + columns / 8 * k + l];
                    assert_eq!(expected, actual);
                }
                let shifted_row = row.iter_mut().map(|el| *el >> 1).collect::<Vec<u8>>();
                row.copy_from_slice(&shifted_row);
            }
        }
    }
}
