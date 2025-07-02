use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use bit_operations::{bitwise_xor, bitwise_and};
use keccak_permutation::KeccakPermutationGadget;

/// SHAKE256 gadget implementing full Keccak-f[1600] permutation
/// Based on FIPS 202 specification with rate = 136 bytes (1088 bits)
pub struct Shake256Gadget;

/// Keccak constants
const SHAKE256_RATE: usize = 136; // 1088 bits / 8 = 136 bytes

impl Shake256Gadget {
    /// Main SHAKE256 hash function
    /// Implements the full sponge construction with Keccak-f[1600]
    pub fn hash<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        input: &[Target],
        output_len: usize,
    ) -> Vec<Target> {
        // Initialize Keccak state (25 lanes of 64 bits each, represented as 32-bit targets)
        let mut state = vec![builder.zero(); 50]; // 25 * 2 for 64-bit lanes as pairs of 32-bit targets
        
        // Pad input according to SHAKE256 specification (10*1 padding)
        let padded_input = Self::pad_shake256(builder, input);
        
        // Absorb phase: process input in rate-sized blocks
        let mut offset = 0;
        while offset + SHAKE256_RATE <= padded_input.len() {
            // XOR rate portion with state
            for i in 0..SHAKE256_RATE {
                let byte_idx = i;
                let lane_idx = byte_idx / 8;
                let byte_in_lane = byte_idx % 8;
                let target_idx = lane_idx * 2 + if byte_in_lane < 4 { 0 } else { 1 };
                
                if target_idx < state.len() {
                    state[target_idx] = bitwise_xor(builder, state[target_idx], padded_input[offset + i]);
                }
            }
            
            // Apply Keccak-f[1600] permutation
            KeccakPermutationGadget::permute(builder, &mut state);
            offset += SHAKE256_RATE;
        }
        
        // Squeeze phase: extract output
        let mut output = Vec::new();
        let mut extracted = 0;
        
        while extracted < output_len {
            // Extract bytes from current state
            let bytes_to_extract = std::cmp::min(SHAKE256_RATE, output_len - extracted);
            
            for i in 0..bytes_to_extract {
                let lane_idx = i / 8;
                let byte_in_lane = i % 8;
                let target_idx = lane_idx * 2 + if byte_in_lane < 4 { 0 } else { 1 };
                
                if target_idx < state.len() {
                    // Extract byte from the appropriate position in the 32-bit target
                    let shift = (byte_in_lane % 4) * 8;
                    let shifted_state = if shift > 0 {
                        // Right shift by dividing
                        let divisor = builder.constant(F::from_canonical_u32(1 << shift));
                        builder.div(state[target_idx], divisor)
                    } else {
                        state[target_idx]
                    };
                    let mask = builder.constant(F::from_canonical_u32(0xFF));
                    let byte_val = bitwise_and(builder, shifted_state, mask);
                    output.push(byte_val);
                }
            }
            
            extracted += bytes_to_extract;
            
            // If we need more output, apply Keccak-f again
            if extracted < output_len {
                KeccakPermutationGadget::permute(builder, &mut state);
            }
        }
        
        output
    }
    
    /// Pad input according to SHAKE256 specification
    /// Uses 10*1 padding: append '1', then zeros, then '1' to reach multiple of rate
    fn pad_shake256<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        input: &[Target],
    ) -> Vec<Target> {
        let mut padded = input.to_vec();
        
        // SHAKE256 uses domain separation suffix 0x1F (for SHAKE)
        padded.push(builder.constant(F::from_canonical_u32(0x1F)));
        
        // Pad with zeros until we reach rate boundary minus 1
        while (padded.len() % SHAKE256_RATE) != (SHAKE256_RATE - 1) {
            padded.push(builder.zero());
        }
        
        // Final padding bit (sets MSB of last byte)
        padded.push(builder.constant(F::from_canonical_u32(0x80)));
        
        padded
    }
    
}

#[cfg(test)]
mod tests;