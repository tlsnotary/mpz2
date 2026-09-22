//! Blake3 compression circuit.

use std::array::from_fn;

use crate::{
    Circuit, CircuitBuilder, Feed, Node,
    ops::{wrapping_add, xor},
};

// Permutation schedule used in Blake3 hashing.
// Ref: https://github.com/BLAKE3-team/BLAKE3/blob/3a90f0f06a429e6ce1d337b28156a75d2a372d7b/reference_impl/reference_impl.rs#L39.
pub(crate) const MSG_PERMUTATION: [usize; 16] =
    [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

type State = [[Node<Feed>; 32]; 16];
type Msg = [[Node<Feed>; 32]; 16];

/// Returns a Blake3 compression circuit with the following signature:
///
/// `fn(msg: [u32; 16], state: [u32; 16]) -> [u32; 16]`
pub fn compress() -> Circuit {
    let mut builder = CircuitBuilder::new();

    let msg: Msg = from_fn(|_| from_fn(|_| builder.add_input()));
    let state: State = from_fn(|_| from_fn(|_| builder.add_input()));

    let output = compress_internal(&mut builder, msg, state);

    for word in output {
        for node in word {
            builder.add_output(node);
        }
    }

    builder.build().unwrap()
}

// Mix function used in Blake3 hashing.
// Ref: https://github.com/BLAKE3-team/BLAKE3/blob/3a90f0f06a429e6ce1d337b28156a75d2a372d7b/reference_impl/reference_impl.rs#L41-L51.
fn mix(
    builder: &mut CircuitBuilder,
    state: &mut State,
    msg: &Msg,
    state_indices: (usize, usize, usize, usize),
    msg_indices: (usize, usize),
) {
    // Note that bits are stored in LSB0 order, so the word-wise rightward
    // rotation translates to a leftward rotation of the bitslice.

    let (a, b, c, d) = state_indices;
    let (mx, my) = msg_indices;
    state[a] = wrapping_add(builder, &state[a], &state[b])
        .as_slice()
        .try_into()
        .unwrap();
    state[a] = wrapping_add(builder, &state[a], &msg[mx])
        .as_slice()
        .try_into()
        .unwrap();

    state[d] = xor(builder, state[d], state[a]);
    state[d].rotate_left(16);

    state[c] = wrapping_add(builder, &state[c], &state[d])
        .as_slice()
        .try_into()
        .unwrap();

    state[b] = xor(builder, state[b], state[c]);
    state[b].rotate_left(12);

    state[a] = wrapping_add(builder, &state[a], &state[b])
        .as_slice()
        .try_into()
        .unwrap();
    state[a] = wrapping_add(builder, &state[a], &msg[my])
        .as_slice()
        .try_into()
        .unwrap();

    state[d] = xor(builder, state[d], state[a]);
    state[d].rotate_left(8);

    state[c] = wrapping_add(builder, &state[c], &state[d])
        .as_slice()
        .try_into()
        .unwrap();

    state[b] = xor(builder, state[b], state[c]);
    state[b].rotate_left(7);
}

// Round function used in Blake3 hashing.
// Ref: https://github.com/BLAKE3-team/BLAKE3/blob/3a90f0f06a429e6ce1d337b28156a75d2a372d7b/reference_impl/reference_impl.rs#L53-L64.
fn round(builder: &mut CircuitBuilder, state: &mut State, msg: &Msg) {
    // Mix columns.
    mix(builder, state, msg, (0, 4, 8, 12), (0, 1));
    mix(builder, state, msg, (1, 5, 9, 13), (2, 3));
    mix(builder, state, msg, (2, 6, 10, 14), (4, 5));
    mix(builder, state, msg, (3, 7, 11, 15), (6, 7));

    // Mix diagonals.
    mix(builder, state, msg, (0, 5, 10, 15), (8, 9));
    mix(builder, state, msg, (1, 6, 11, 12), (10, 11));
    mix(builder, state, msg, (2, 7, 8, 13), (12, 13));
    mix(builder, state, msg, (3, 4, 9, 14), (14, 15));
}

// Permute function used in Blake3 hashing.
// Ref: https://github.com/BLAKE3-team/BLAKE3/blob/3a90f0f06a429e6ce1d337b28156a75d2a372d7b/reference_impl/reference_impl.rs#L66-L72.
fn permute(msg: Msg) -> Msg {
    from_fn(|i| msg[MSG_PERMUTATION[i]])
}

// Compress function used in Blake3 hashing.
// Ref: https://github.com/BLAKE3-team/BLAKE3/blob/3a90f0f06a429e6ce1d337b28156a75d2a372d7b/reference_impl/reference_impl.rs#L74-L111.
fn compress_internal(builder: &mut CircuitBuilder, mut msg: Msg, state: State) -> State {
    const NO_OF_ROUNDS: usize = 7;

    let mut running_state = state;

    for _ in 0..NO_OF_ROUNDS - 1 {
        round(builder, &mut running_state, &msg);
        msg = permute(msg);
    }
    round(builder, &mut running_state, &msg);

    for i in 0..8 {
        running_state[i] = xor(builder, running_state[i], running_state[i + 8]);
        running_state[i + 8] = xor(builder, running_state[i + 8], state[i]);
    }

    running_state
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evaluate;

    #[test]
    #[allow(clippy::same_item_push)]
    #[allow(clippy::needless_range_loop)]
    #[allow(clippy::vec_init_then_push)]
    fn test_blake3_mix() {
        let mut builder = CircuitBuilder::new();

        // Create inputs for the 16 state values and 16 message values
        let mut state: [[_; 32]; 16] = from_fn(|_| from_fn(|_| builder.add_input()));
        let msg: [[_; 32]; 16] = from_fn(|_| from_fn(|_| builder.add_input()));

        // Apply mix_alt to positions 0, 1, 2, 3 with message indices 0, 1
        mix(&mut builder, &mut state, &msg, (0, 1, 2, 3), (0, 1));

        // Add outputs (1st 4 state values)
        for (i, state_word) in state.into_iter().enumerate() {
            if i < 4 {
                for node in state_word {
                    builder.add_output(node);
                }
            }
        }

        let circ = builder.build().unwrap();

        // Test case 1: All ones
        {
            let mut state = [1u32; 16];
            reference::mix(&mut state, 0, 1, 2, 3, 1u32, 1u32);

            let mut input_values = Vec::new();
            // Add state values
            for _ in 0..16 {
                input_values.push(1u32);
            }
            // Add message values
            for _ in 0..16 {
                input_values.push(1u32);
            }

            let output: Vec<u32> = evaluate!(&circ, input_values).unwrap();

            for i in 0..4 {
                assert_eq!(output[i], state[i], "Test 1: State[{i}] mismatch");
            }
        }

        // Test case 2: All zeros (edge case)
        {
            let mut state = [0u32; 16];
            reference::mix(&mut state, 0, 1, 2, 3, 0u32, 0u32);

            let mut input_values = Vec::new();
            // Add state values
            for _ in 0..16 {
                input_values.push(0u32);
            }
            // Add message values
            for _ in 0..16 {
                input_values.push(0u32);
            }

            let output: Vec<u32> = evaluate!(&circ, input_values).unwrap();

            for i in 0..4 {
                assert_eq!(output[i], state[i], "Test 2: State[{i}] mismatch");
            }
        }

        // Test case 3: Max values (overflow testing)
        {
            let mut state = [u32::MAX; 16];
            reference::mix(&mut state, 0, 1, 2, 3, u32::MAX, u32::MAX);

            let mut input_values = Vec::new();
            // Add state values
            for _ in 0..16 {
                input_values.push(u32::MAX);
            }
            // Add message values
            for _ in 0..16 {
                input_values.push(u32::MAX);
            }

            let output: Vec<u32> = evaluate!(&circ, input_values).unwrap();

            for i in 0..4 {
                assert_eq!(output[i], state[i], "Test 3: State[{i}] mismatch");
            }
        }

        // Test case 4: Sequential values
        {
            let mut state = [0u32; 16];
            for i in 0..16 {
                state[i] = i as u32;
            }
            reference::mix(&mut state, 0, 1, 2, 3, 16u32, 17u32);

            let mut input_values = Vec::new();
            // Add state values (0..16)
            for i in 0..16 {
                input_values.push(i as u32);
            }
            // Add message values (16..32)
            for i in 16..32 {
                input_values.push(i as u32);
            }

            let output: Vec<u32> = evaluate!(&circ, input_values).unwrap();

            for i in 0..4 {
                assert_eq!(output[i], state[i], "Test 4: State[{i}] mismatch");
            }
        }

        // Test case 5: Powers of two
        {
            let mut state = [0u32; 16];
            for i in 0..16 {
                state[i] = 1u32 << (i % 16);
            }
            let msg_vals = [1u32 << 16, 1u32 << 17];
            reference::mix(&mut state, 0, 1, 2, 3, msg_vals[0], msg_vals[1]);

            let mut input_values = Vec::new();
            // Add state values
            for i in 0..16 {
                input_values.push(1u32 << (i % 16));
            }
            // Add message values
            input_values.push(1u32 << 16); // msg[0]
            input_values.push(1u32 << 17); // msg[1]
            for _ in 2..16 {
                input_values.push(0u32);
            }

            let output: Vec<u32> = evaluate!(&circ, input_values).unwrap();

            for i in 0..4 {
                assert_eq!(output[i], state[i], "Test 5: State[{i}] mismatch");
            }
        }

        // Test case 6: Mix of zero and non-zero values
        {
            let mut state = [0u32; 16];
            state[0] = 0u32;
            state[1] = u32::MAX;
            state[2] = 0u32;
            state[3] = u32::MAX;
            reference::mix(&mut state, 0, 1, 2, 3, 0x12345678u32, 0x9abcdef0u32);

            let mut input_values = Vec::new();
            // Add state values
            input_values.push(0u32);
            input_values.push(u32::MAX);
            input_values.push(0u32);
            input_values.push(u32::MAX);
            for _ in 4..16 {
                input_values.push(0u32);
            }
            // Add message values
            input_values.push(0x12345678u32); // msg[0]
            input_values.push(0x9abcdef0u32); // msg[1]
            for _ in 2..16 {
                input_values.push(0u32);
            }

            let output: Vec<u32> = evaluate!(&circ, input_values).unwrap();

            for i in 0..4 {
                assert_eq!(output[i], state[i], "Test 6: State[{i}] mismatch");
            }
        }

        // Test case 7: Large random-like values
        {
            let mut state = [0u32; 16];
            state[0] = 0xdeadbeefu32;
            state[1] = 0xcafebabeu32;
            state[2] = 0xfeedfaceu32;
            state[3] = 0xbadc0dedu32;
            reference::mix(&mut state, 0, 1, 2, 3, 0x11111111u32, 0x22222222u32);

            let mut input_values = Vec::new();
            // Add state values
            input_values.push(0xdeadbeefu32);
            input_values.push(0xcafebabeu32);
            input_values.push(0xfeedfaceu32);
            input_values.push(0xbadc0dedu32);
            for _ in 4..16 {
                input_values.push(0u32);
            }
            // Add message values
            input_values.push(0x11111111u32); // msg[0]
            input_values.push(0x22222222u32); // msg[1]
            for _ in 2..16 {
                input_values.push(0u32);
            }

            let output: Vec<u32> = evaluate!(&circ, input_values).unwrap();

            for i in 0..4 {
                assert_eq!(output[i], state[i], "Test 7: State[{i}] mismatch");
            }
        }

        // Test case 8: Values with alternating bit patterns
        {
            let mut state = [0u32; 16];
            state[0] = 0xAAAAAAAAu32;
            state[1] = 0x55555555u32;
            state[2] = 0xFFFF0000u32;
            state[3] = 0x0000FFFFu32;
            reference::mix(&mut state, 0, 1, 2, 3, 0xF0F0F0F0u32, 0x0F0F0F0Fu32);

            let mut input_values = Vec::new();
            // Add state values
            input_values.push(0xAAAAAAAAu32);
            input_values.push(0x55555555u32);
            input_values.push(0xFFFF0000u32);
            input_values.push(0x0000FFFFu32);
            for _ in 4..16 {
                input_values.push(0u32);
            }
            // Add message values
            input_values.push(0xF0F0F0F0u32); // msg[0]
            input_values.push(0x0F0F0F0Fu32); // msg[1]
            for _ in 2..16 {
                input_values.push(0u32);
            }

            let output: Vec<u32> = evaluate!(&circ, input_values).unwrap();

            for i in 0..4 {
                assert_eq!(output[i], state[i], "Test 8: State[{i}] mismatch");
            }
        }

        // Test case 9: Single bit set values
        {
            let mut state = [0u32; 16];
            state[0] = 1u32 << 31;
            state[1] = 1u32 << 15;
            state[2] = 1u32 << 7;
            state[3] = 1u32 << 0;
            reference::mix(&mut state, 0, 1, 2, 3, 1u32 << 16, 1u32 << 8);

            let mut input_values = Vec::new();
            // Add state values
            input_values.push(1u32 << 31);
            input_values.push(1u32 << 15);
            input_values.push(1u32 << 7);
            input_values.push(1u32 << 0);
            for _ in 4..16 {
                input_values.push(0u32);
            }
            // Add message values
            input_values.push(1u32 << 16); // msg[0]
            input_values.push(1u32 << 8); // msg[1]
            for _ in 2..16 {
                input_values.push(0u32);
            }

            let output: Vec<u32> = evaluate!(&circ, input_values).unwrap();

            for i in 0..4 {
                assert_eq!(output[i], state[i], "Test 9: State[{i}] mismatch");
            }
        }
    }

    #[test]
    #[allow(clippy::same_item_push)]
    #[allow(clippy::needless_range_loop)]
    #[allow(clippy::vec_init_then_push)]
    fn test_blake3_round() {
        use std::array::from_fn;

        use crate::circuits::blake3::round;

        let mut builder = CircuitBuilder::new();

        // Create inputs for the 16 state values and 16 message values
        let mut state: [[_; 32]; 16] = from_fn(|_| from_fn(|_| builder.add_input()));
        let msg: [[_; 32]; 16] = from_fn(|_| from_fn(|_| builder.add_input()));

        round(&mut builder, &mut state, &msg);

        // Add outputs
        for state_word in state {
            for node in state_word {
                builder.add_output(node);
            }
        }

        let circ = builder.build().unwrap();

        // Test with sequential values
        let mut expected_state = [0u32; 16];
        for i in 0..16 {
            expected_state[i] = i as u32;
        }

        let test_m = [0u32; 16];
        reference::round(&mut expected_state, &test_m);

        // Prepare input values
        let mut input_values = Vec::new();
        // Add state values (0..16)
        for i in 0..16 {
            input_values.push(i as u32);
        }
        // Add message values (all zeros)
        for _ in 0..16 {
            input_values.push(0u32);
        }

        // Evaluate circuit
        let output: Vec<u32> = evaluate!(&circ, input_values).unwrap();

        // Check results
        for i in 0..16 {
            assert_eq!(output[i], expected_state[i], "State[{i}] mismatch");
        }
    }

    #[test]
    #[allow(clippy::same_item_push)]
    #[allow(clippy::needless_range_loop)]
    #[allow(clippy::vec_init_then_push)]
    fn test_blake3_compress() {
        use crate::circuits::blake3::compress;

        let circ = compress();

        // Test case 1: All zeros
        {
            let mut test_state = [0u32; 16];
            let mut test_msg = [0u32; 16];
            reference::compress(&mut test_msg, &mut test_state);

            let mut input_values = Vec::new();
            // Add message values (all zeros)
            for _ in 0..16 {
                input_values.push(0u32);
            }
            // Add state values (all zeros)
            for _ in 0..16 {
                input_values.push(0u32);
            }

            let output: Vec<u32> = evaluate!(&circ, input_values).unwrap();

            for i in 0..16 {
                assert_eq!(output[i], test_state[i], "Test 1: State[{i}] mismatch");
            }
        }

        // Test case 2: Sequential values for state, zeros for message
        {
            let mut test_state = [0u32; 16];
            for i in 0..16 {
                test_state[i] = i as u32;
            }
            let mut test_msg = [0u32; 16];
            reference::compress(&mut test_msg, &mut test_state);

            let mut input_values = Vec::new();
            // Add message values (all zeros)
            for _ in 0..16 {
                input_values.push(0u32);
            }
            // Add state values (0..16)
            for i in 0..16 {
                input_values.push(i as u32);
            }

            let output: Vec<u32> = evaluate!(&circ, input_values).unwrap();

            for i in 0..16 {
                assert_eq!(output[i], test_state[i], "Test 2: State[{i}] mismatch");
            }
        }

        // Test case 3: All ones
        {
            let mut test_state = [1u32; 16];
            let mut test_msg = [1u32; 16];
            reference::compress(&mut test_msg, &mut test_state);

            let mut input_values = Vec::new();
            // Add message values (all ones)
            for _ in 0..16 {
                input_values.push(1u32);
            }
            // Add state values (all ones)
            for _ in 0..16 {
                input_values.push(1u32);
            }

            let output: Vec<u32> = evaluate!(&circ, input_values).unwrap();

            for i in 0..16 {
                assert_eq!(output[i], test_state[i], "Test 3: State[{i}] mismatch");
            }
        }

        // Test case 4: Powers of two pattern
        {
            let mut test_state = [0u32; 16];
            let mut test_msg = [0u32; 16];
            for i in 0..16 {
                test_state[i] = 1u32 << (i % 32);
                test_msg[i] = 1u32 << ((i + 16) % 32);
            }
            reference::compress(&mut test_msg, &mut test_state);

            let mut input_values = Vec::new();
            // Add message values
            for i in 0..16 {
                input_values.push(1u32 << ((i + 16) % 32));
            }
            // Add state values
            for i in 0..16 {
                input_values.push(1u32 << (i % 32));
            }

            let output: Vec<u32> = evaluate!(&circ, input_values).unwrap();

            for i in 0..16 {
                assert_eq!(output[i], test_state[i], "Test 4: State[{i}] mismatch");
            }
        }

        // Test case 5: Alternating pattern
        {
            let mut test_state = [0u32; 16];
            let mut test_msg = [0u32; 16];
            for i in 0..16 {
                test_state[i] = if i % 2 == 0 { 0xAAAAAAAA } else { 0x55555555 };
                test_msg[i] = if i % 2 == 0 { 0x0F0F0F0F } else { 0xF0F0F0F0 };
            }
            reference::compress(&mut test_msg, &mut test_state);

            let mut input_values = Vec::new();
            // Add message values
            for i in 0..16 {
                input_values.push(if i % 2 == 0 {
                    0x0F0F0F0Fu32
                } else {
                    0xF0F0F0F0u32
                });
            }
            // Add state values
            for i in 0..16 {
                input_values.push(if i % 2 == 0 {
                    0xAAAAAAAAu32
                } else {
                    0x55555555u32
                });
            }

            let output: Vec<u32> = evaluate!(&circ, input_values).unwrap();

            for i in 0..16 {
                assert_eq!(output[i], test_state[i], "Test 5: State[{i}] mismatch");
            }
        }

        // Test case 6: Max values (overflow testing)
        {
            let mut test_state = [u32::MAX; 16];
            let mut test_msg = [u32::MAX; 16];
            reference::compress(&mut test_msg, &mut test_state);

            let mut input_values = Vec::new();
            // Add message values (all MAX)
            for _ in 0..16 {
                input_values.push(u32::MAX);
            }
            // Add state values (all MAX)
            for _ in 0..16 {
                input_values.push(u32::MAX);
            }

            let output: Vec<u32> = evaluate!(&circ, input_values).unwrap();

            for i in 0..16 {
                assert_eq!(output[i], test_state[i], "Test 6: State[{i}] mismatch");
            }
        }
    }

    mod reference {
        use super::MSG_PERMUTATION;

        // Ref: https://github.com/BLAKE3-team/BLAKE3/blob/3a90f0f06a429e6ce1d337b28156a75d2a372d7b/reference_impl/reference_impl.rs#L41-L51.
        pub(crate) fn mix(
            state: &mut [u32; 16],
            a: usize,
            b: usize,
            c: usize,
            d: usize,
            mx: u32,
            my: u32,
        ) {
            state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
            state[d] = (state[d] ^ state[a]).rotate_right(16);
            state[c] = state[c].wrapping_add(state[d]);
            state[b] = (state[b] ^ state[c]).rotate_right(12);
            state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
            state[d] = (state[d] ^ state[a]).rotate_right(8);
            state[c] = state[c].wrapping_add(state[d]);
            state[b] = (state[b] ^ state[c]).rotate_right(7);
        }

        // Ref: https://github.com/BLAKE3-team/BLAKE3/blob/3a90f0f06a429e6ce1d337b28156a75d2a372d7b/reference_impl/reference_impl.rs#L53-L64.
        pub(crate) fn round(state: &mut [u32; 16], m: &[u32; 16]) {
            // Mix the columns.
            mix(state, 0, 4, 8, 12, m[0], m[1]);
            mix(state, 1, 5, 9, 13, m[2], m[3]);
            mix(state, 2, 6, 10, 14, m[4], m[5]);
            mix(state, 3, 7, 11, 15, m[6], m[7]);
            // Mix the diagonals.
            mix(state, 0, 5, 10, 15, m[8], m[9]);
            mix(state, 1, 6, 11, 12, m[10], m[11]);
            mix(state, 2, 7, 8, 13, m[12], m[13]);
            mix(state, 3, 4, 9, 14, m[14], m[15]);
        }

        // Ref: https://github.com/BLAKE3-team/BLAKE3/blob/3a90f0f06a429e6ce1d337b28156a75d2a372d7b/reference_impl/reference_impl.rs#L66-L72.
        pub(crate) fn permute(m: &mut [u32; 16]) {
            let mut permuted = [0; 16];
            for i in 0..16 {
                permuted[i] = m[MSG_PERMUTATION[i]];
            }
            *m = permuted;
        }

        // Ref: https://github.com/BLAKE3-team/BLAKE3/blob/3a90f0f06a429e6ce1d337b28156a75d2a372d7b/reference_impl/reference_impl.rs#L74-L111.
        pub(crate) fn compress(block: &mut [u32; 16], state: &mut [u32; 16]) {
            let initial_state = *state;

            round(state, block); // round 1
            permute(block);
            round(state, block); // round 2
            permute(block);
            round(state, block); // round 3
            permute(block);
            round(state, block); // round 4
            permute(block);
            round(state, block); // round 5
            permute(block);
            round(state, block); // round 6
            permute(block);
            round(state, block); // round 7

            for i in 0..8 {
                state[i] ^= state[i + 8];
                state[i + 8] ^= initial_state[i];
            }
        }
    }
}
