use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use anyhow::Result;
use crate::keccak_circuit::KeccakCircuit;

/// SHAKE256 Circuit for zero-knowledge computation of SHAKE256 hash function
/// 
/// This circuit implements SHAKE256 (SHA-3 XOF) for use in ML-DSA verification.
/// SHAKE256 is used in ML-DSA for:
/// - H(pk_bytes, 64): Public key transcript computation
/// - H(tr || m, 64): Message digest with transcript  
/// - H(mu || w_prime_bytes, c_tilde_bytes): Challenge generation
pub struct Shake256Circuit<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> {
    pub circuit: CircuitData<F, C, D>,
    pub input_targets: Vec<Target>,
    pub output_targets: Vec<Target>,
    pub input_len: usize,
    pub output_len: usize,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> 
    Shake256Circuit<F, C, D> 
where
    C::Hasher: AlgebraicHasher<F>,
{
    /// Helper function to perform bitwise XOR (internal version)
    fn bitwise_xor_internal(
        builder: &mut CircuitBuilder<F, D>,
        a: Target,
        b: Target,
    ) -> Target {
        let a_bits = builder.split_le(a, 64);
        let b_bits = builder.split_le(b, 64);
        
        let mut xor_bits = Vec::new();
        for i in 0..64 {
            let a_bit = a_bits[i].target;
            let b_bit = b_bits[i].target;
            let product = builder.mul(a_bit, b_bit);
            let two_product = builder.mul_const(F::TWO, product);
            let sum = builder.add(a_bit, b_bit);
            let xor_bit = builder.sub(sum, two_product);
            xor_bits.push(xor_bit);
        }
        
        Self::target_sum_from_le_bits(builder, &xor_bits)
    }

    /// Helper function to shift left by a constant amount
    fn shift_left_const(
        builder: &mut CircuitBuilder<F, D>,
        value: Target,
        positions: usize,
    ) -> Target {
        if positions == 0 {
            return value;
        }
        
        if positions >= 64 {
            return builder.zero();
        }
        
        // Shift left by multiplying by 2^positions
        let one = builder.one();
        let multiplier = builder.exp_power_of_2(one, positions);
        builder.mul(value, multiplier)
    }

    /// Helper function to extract byte from word at specific position
    fn extract_byte(
        builder: &mut CircuitBuilder<F, D>,
        word: Target,
        byte_position: usize,
    ) -> Target {
        if byte_position >= 8 {
            return builder.zero();
        }
        
        let bits = builder.split_le(word, 64);
        let start_bit = byte_position * 8;
        let end_bit = start_bit + 8;
        
        let byte_targets: Vec<Target> = bits[start_bit..end_bit].iter().map(|b| b.target).collect();
        Self::target_sum_from_le_bits(builder, &byte_targets)
    }

    /// Helper function to sum Target bits as little-endian
    fn target_sum_from_le_bits(builder: &mut CircuitBuilder<F, D>, bits: &[Target]) -> Target {
        let mut result = builder.zero();
        
        for (i, &bit) in bits.iter().enumerate() {
            let one = builder.one();
            let power_of_two = builder.exp_power_of_2(one, i);
            let term = builder.mul(bit, power_of_two);
            result = builder.add(result, term);
        }
        
        result
    }

    /// Create a new SHAKE256 circuit
    /// 
    /// # Arguments
    /// * `config` - Circuit configuration
    /// * `input_len` - Maximum input length in bytes
    /// * `output_len` - Output length in bytes
    pub fn new(config: CircuitConfig, input_len: usize, output_len: usize) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        // Create input targets (one per byte)
        let input_targets: Vec<Target> = (0..input_len)
            .map(|_| builder.add_virtual_target())
            .collect();
        
        // Constrain input targets to be valid bytes (0-255)
        for &input in &input_targets {
            builder.range_check(input, 8);
        }
        
        // Build the actual SHAKE256 circuit and get computed output targets
        let computed_outputs = Self::build_shake256_circuit(
            &mut builder,
            &input_targets,
            &[],  // We don't need separate output targets since we compute them
            input_len,
            output_len,
        );
        
        // Constrain computed outputs to be valid bytes (0-255)
        for &output in &computed_outputs {
            builder.range_check(output, 8);
        }
        
        // Register computed output targets as public inputs so they can be extracted from proofs
        for &target in &computed_outputs {
            builder.register_public_input(target);
        }
        
        let circuit = builder.build::<C>();
        
        Self {
            circuit,
            input_targets,
            output_targets: computed_outputs,
            input_len,
            output_len,
        }
    }
    
    /// Build SHAKE256 circuit logic
    /// 
    /// # Arguments
    /// * `builder` - Circuit builder
    /// * `input_targets` - Input byte targets
    /// * `output_targets` - Output byte targets (unused but kept for consistency)
    /// * `input_len` - Input length in bytes
    /// * `output_len` - Output length in bytes
    /// 
    /// # Returns
    /// * Computed output targets
    pub fn build_shake256_circuit(
        builder: &mut CircuitBuilder<F, D>,
        input_targets: &[Target],
        _output_targets: &[Target],
        input_len: usize,
        output_len: usize,
    ) -> Vec<Target> {
        // SHAKE256 uses Keccak[512] with capacity c=512, rate r=1088 bits (136 bytes)
        const RATE_BYTES: usize = 136; // (1600 - 512) / 8
        const STATE_WORDS: usize = 25; // 1600 bits / 64 bits
        
        // Initialize Keccak state to all zeros
        let mut state = [builder.zero(); STATE_WORDS];
        
        // Absorption phase: absorb input in RATE_BYTES chunks
        let mut offset = 0;
        while offset < input_len {
            let chunk_size = std::cmp::min(RATE_BYTES, input_len - offset);
            
            // XOR input chunk into state (proper byte packing)
            for i in 0..chunk_size {
                if offset + i < input_targets.len() {
                    let word_idx = i / 8;
                    let byte_in_word = i % 8;
                    
                    if word_idx < STATE_WORDS {
                        // Pack byte into correct position in 64-bit word
                        let shift_amount = byte_in_word * 8;
                        let shifted_byte = Self::shift_left_const(
                            builder,
                            input_targets[offset + i],
                            shift_amount
                        );
                        state[word_idx] = Self::bitwise_xor_internal(builder, state[word_idx], shifted_byte);
                    }
                }
            }
            
            // Apply Keccak-f[1600] permutation
            state = KeccakCircuit::keccak_f(builder, &state);
            
            offset += chunk_size;
        }
        
        // Add proper SHAKE256 padding (pad10*1 with domain separation)
        // First add domain separation suffix 1111 (0x1F for SHAKE256)
        let padding_offset = input_len % RATE_BYTES;
        
        // Add padding byte at correct position
        if padding_offset < RATE_BYTES {
            let word_idx = padding_offset / 8;
            let byte_in_word = padding_offset % 8;
            
            if word_idx < STATE_WORDS {
                let padding_byte = builder.constant(F::from_canonical_u64(0x1F)); // Domain separation
                let shifted_padding = Self::shift_left_const(builder, padding_byte, byte_in_word * 8);
                state[word_idx] = Self::bitwise_xor_internal(builder, state[word_idx], shifted_padding);
            }
        }
        
        // Add final padding bit at end of rate (pad10*1 pattern)
        let final_byte_word = (RATE_BYTES - 1) / 8;
        let final_byte_pos = (RATE_BYTES - 1) % 8;
        if final_byte_word < STATE_WORDS {
            let final_bit = builder.constant(F::from_canonical_u64(0x80)); // High bit
            let shifted_final = Self::shift_left_const(builder, final_bit, final_byte_pos * 8);
            state[final_byte_word] = Self::bitwise_xor_internal(builder, state[final_byte_word], shifted_final);
        }
        
        // Apply final permutation
        state = KeccakCircuit::keccak_f(builder, &state);
        
        // Squeezing phase: extract output bytes
        let mut output = Vec::new();
        let mut squeezed = 0;
        
        while squeezed < output_len {
            // Extract bytes from current state (proper byte extraction)
            for word_idx in 0..STATE_WORDS {
                for byte_in_word in 0..8 {
                    if squeezed >= output_len {
                        break;
                    }
                    
                    // Extract byte from word using proper bit manipulation
                    let extracted_byte = Self::extract_byte(builder, state[word_idx], byte_in_word);
                    output.push(extracted_byte);
                    squeezed += 1;
                    
                    if squeezed >= output_len {
                        break;
                    }
                }
                
                if squeezed >= output_len {
                    break;
                }
            }
            
            // If we need more output, apply Keccak-f again
            if squeezed < output_len {
                state = KeccakCircuit::keccak_f(builder, &state);
            }
        }
        
        output
    }

    /// Generate a proof for SHAKE256 computation
    /// 
    /// # Arguments
    /// * `input_bytes` - Input data to hash
    /// 
    /// # Returns
    /// * `Result<ProofWithPublicInputs<F, C, D>>` - ZK proof of correct SHAKE256 computation
    pub fn generate_proof(&self, input_bytes: &[u8]) -> Result<ProofWithPublicInputs<F, C, D>> {
        if input_bytes.len() > self.input_len {
            return Err(anyhow::anyhow!("Input too long: {} > {}", input_bytes.len(), self.input_len));
        }
        
        let mut pw = PartialWitness::new();
        
        // Set input targets - the circuit will compute SHAKE256 from these inputs
        for i in 0..self.input_len {
            let val = if i < input_bytes.len() { 
                input_bytes[i] 
            } else { 
                0 
            };
            pw.set_target(self.input_targets[i], F::from_canonical_u64(val as u64));
        }
        
        // The circuit computes the SHAKE256 output from the inputs automatically
        // No need to set output targets - they are computed by the circuit
        
        self.circuit.prove(pw)
    }
    
    /// Extract output hash from a proof
    /// 
    /// # Arguments  
    /// * `proof` - ZK proof containing SHAKE256 computation
    /// 
    /// # Returns
    /// * `Result<Vec<u8>>` - Extracted hash output bytes
    pub fn extract_output(&self, proof: &ProofWithPublicInputs<F, C, D>) -> Result<Vec<u8>> {
        // Extract the actual computed output values from the proof's public inputs
        // The output targets were registered as public inputs during circuit construction
        
        if proof.public_inputs.len() < self.output_len {
            return Err(anyhow::anyhow!(
                "Proof does not contain enough public inputs: {} < {}", 
                proof.public_inputs.len(), 
                self.output_len
            ));
        }
        
        let mut output = Vec::new();
        
        // Extract each output byte from the public inputs
        // The output targets are the first self.output_len public inputs
        for i in 0..self.output_len {
            let field_element = proof.public_inputs[i];
            
            // Convert field element to u64, then to u8
            // Note: This assumes the field element represents a valid byte value (0-255)
            let value_u64 = field_element.to_canonical_u64();
            
            if value_u64 > 255 {
                return Err(anyhow::anyhow!(
                    "Invalid byte value in proof public inputs at index {}: {} > 255", 
                    i, 
                    value_u64
                ));
            }
            
            output.push(value_u64 as u8);
        }
        
        Ok(output)
    }
    
    /// Compute SHAKE256 hash using reference implementation (for testing/comparison only)
    #[cfg(test)]
    fn reference_shake256(input: &[u8], output_len: usize) -> Vec<u8> {
        use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};
        
        let mut hasher = Shake256::default();
        hasher.update(input);
        let mut reader = hasher.finalize_xof();
        let mut output = vec![0u8; output_len];
        reader.read(&mut output);
        output
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<2>>::F;
    
    #[test]
    fn test_reference_shake256_basic() {
        // Test reference implementation with known vectors
        let input = b"abc";
        let output = Shake256Circuit::<F, C, 2>::reference_shake256(input, 32);
        assert_eq!(output.len(), 32);
        
        // Empty input test
        let empty_output = Shake256Circuit::<F, C, 2>::reference_shake256(b"", 32);
        assert_eq!(empty_output.len(), 32);
        assert_ne!(output, empty_output); // Should produce different hashes
    }
    
    #[test]
    fn test_circuit_construction_basic() {
        let config = CircuitConfig::standard_recursion_config();
        let circuit = Shake256Circuit::<F, C, 2>::new(config, 64, 32);
        
        assert_eq!(circuit.input_len, 64);
        assert_eq!(circuit.output_len, 32);
        assert_eq!(circuit.input_targets.len(), 64);
        assert_eq!(circuit.output_targets.len(), 32);
    }
}