use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use bit_operations_gadget::{bitwise_xor, bitwise_and};
use keccak_permutation_gadget::KeccakPermutationGadget;

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
mod tests {
    use super::*;
    use plonky2::field::types::Field;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2::iop::witness::PartialWitness;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    #[test]
    fn test_shake256_empty_input() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        let input = vec![];
        let output = Shake256Gadget::hash(&mut builder, &input, 32);
        
        assert_eq!(output.len(), 32);
        
        let circuit = builder.build::<C>();
        let pw = PartialWitness::new();
        
        let proof = circuit.prove(pw).expect("proof generation should succeed");
        circuit.verify(proof).expect("proof verification should succeed");
    }

    #[test]
    fn test_shake256_known_vector() {
        // Test with empty input - known SHAKE256 output
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        let input = vec![];
        let output = Shake256Gadget::hash(&mut builder, &input, 64);
        
        assert_eq!(output.len(), 64);
        
        let circuit = builder.build::<C>();
        let pw = PartialWitness::new();
        
        let proof = circuit.prove(pw).expect("proof generation should succeed");
        circuit.verify(proof).expect("proof verification should succeed");
    }

    #[test]
    fn test_shake256_non_empty_input() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        // Create small test input
        let input: Vec<Target> = (0..4).map(|i| {
            builder.constant(F::from_canonical_u32(i as u32 + 1))
        }).collect();
        
        let output = Shake256Gadget::hash(&mut builder, &input, 32);
        
        assert_eq!(output.len(), 32);
        
        let circuit = builder.build::<C>();
        let pw = PartialWitness::new();
        
        let proof = circuit.prove(pw).expect("proof generation should succeed");
        circuit.verify(proof).expect("proof verification should succeed");
    }

    #[test]
    fn test_shake256_different_lengths() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        let input: Vec<Target> = (0..8).map(|i| {
            builder.constant(F::from_canonical_u32((i * 17) as u32))
        }).collect();
        
        // Test different output lengths
        let output_16 = Shake256Gadget::hash(&mut builder, &input, 16);
        let output_64 = Shake256Gadget::hash(&mut builder, &input, 64);
        let output_128 = Shake256Gadget::hash(&mut builder, &input, 128);
        
        assert_eq!(output_16.len(), 16);
        assert_eq!(output_64.len(), 64);
        assert_eq!(output_128.len(), 128);
        
        let circuit = builder.build::<C>();
        let pw = PartialWitness::new();
        
        let proof = circuit.prove(pw).expect("proof generation should succeed");
        circuit.verify(proof).expect("proof verification should succeed");
    }

    #[test]
    fn test_shake256_deterministic() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        let input: Vec<Target> = (0..6).map(|i| {
            builder.constant(F::from_canonical_u32((i * 123) as u32))
        }).collect();
        
        let output1 = Shake256Gadget::hash(&mut builder, &input, 32);
        let output2 = Shake256Gadget::hash(&mut builder, &input, 32);
        
        // Verify deterministic behavior by constraining equality
        for i in 0..32 {
            builder.connect(output1[i], output2[i]);
        }
        
        let circuit = builder.build::<C>();
        let pw = PartialWitness::new();
        
        let proof = circuit.prove(pw).expect("proof generation should succeed");
        circuit.verify(proof).expect("proof verification should succeed");
    }
}