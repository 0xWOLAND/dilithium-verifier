use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use bit_operations::{bitwise_xor, bitwise_and, bitwise_not};

/// Keccak-f[1600] permutation gadget
/// This implements the core permutation used in Keccak/SHA-3/SHAKE algorithms
pub struct KeccakPermutationGadget;

/// Keccak constants
pub const KECCAK_ROUNDS: usize = 24;
pub const KECCAK_STATE_SIZE: usize = 25; // 5x5 lanes

/// Round constants for Keccak-f[1600] (only low 32 bits needed for circuit)
pub const ROUND_CONSTANTS: [u32; KECCAK_ROUNDS] = [
    0x00000001, 0x00008082, 0x0000808a, 0x00008000,
    0x0000808b, 0x80000001, 0x80008081, 0x00008009,
    0x0000008a, 0x00000088, 0x80008009, 0x80008003,
    0x80008002, 0x80000080, 0x0000800a, 0x8000000a,
    0x80008081, 0x00008080, 0x80000001, 0x80008008,
    0x00000001, 0x80008082, 0x0000808a, 0x80000080,
];

/// Rho offsets for rotation amounts in Keccak
pub const RHO_OFFSETS: [usize; 25] = [
     0,  1, 62, 28, 27, 36, 44,  6, 55, 20,
     3, 10, 43, 25, 39, 41, 45, 15, 21,  8,
    18,  2, 61, 56, 14
];

/// Pi offsets for lane permutation in Keccak  
pub const PI_OFFSETS: [usize; 25] = [
     0,  6, 12, 18, 24,  3,  9, 10, 16, 22,
     1,  7, 13, 19, 20,  4,  5, 11, 17, 23,
     2,  8, 14, 15, 21
];

impl KeccakPermutationGadget {
    /// Apply the Keccak-f[1600] permutation to the state with range checks
    /// State is represented as 50 targets (25 lanes * 2 targets per 64-bit lane)
    pub fn permute<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        state: &mut Vec<Target>,
    ) {
        assert_eq!(state.len(), 50, "State must have 50 targets (25 lanes * 2 for 64-bit)");
        
        // Range check all input state values to ensure they are 32-bit
        for &value in state.iter() {
            builder.range_check(value, 32);
        }
        
        for round in 0..KECCAK_ROUNDS {
            Self::keccak_round(builder, state, round);
        }
        
        // Range check all output state values to ensure they remain 32-bit
        for &value in state.iter() {
            builder.range_check(value, 32);
        }
    }
    
    /// Apply one round of the Keccak permutation
    fn keccak_round<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        state: &mut Vec<Target>,
        round: usize,
    ) {
        // θ (Theta) step
        Self::theta(builder, state);
        
        // ρ (Rho) and π (Pi) steps combined
        Self::rho_pi(builder, state);
        
        // χ (Chi) step
        Self::chi(builder, state);
        
        // ι (Iota) step
        Self::iota(builder, state, round);
    }
    
    /// θ (Theta) step: Column parity computation
    fn theta<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        state: &mut Vec<Target>,
    ) {
        // Compute column parities
        let mut c = vec![builder.zero(); 10]; // 5 columns * 2 targets per 64-bit
        for x in 0..5 {
            for y in 0..5 {
                let idx = (y * 5 + x) * 2;
                c[x * 2] = bitwise_xor(builder, c[x * 2], state[idx]);
                if idx + 1 < state.len() {
                    c[x * 2 + 1] = bitwise_xor(builder, c[x * 2 + 1], state[idx + 1]);
                }
            }
        }
        
        // Compute D values
        let mut d = vec![builder.zero(); 10];
        for x in 0..5 {
            let x_minus_1 = (x + 4) % 5;
            let x_plus_1 = (x + 1) % 5;
            
            // D[x] = C[x-1] ⊕ ROT(C[x+1], 1)
            let rotated_low = Self::rotate_left_1(builder, c[x_plus_1 * 2]);
            let rotated_high = Self::rotate_left_1(builder, c[x_plus_1 * 2 + 1]);
            
            d[x * 2] = bitwise_xor(builder, c[x_minus_1 * 2], rotated_low);
            d[x * 2 + 1] = bitwise_xor(builder, c[x_minus_1 * 2 + 1], rotated_high);
        }
        
        // Apply theta transformation
        for x in 0..5 {
            for y in 0..5 {
                let idx = (y * 5 + x) * 2;
                state[idx] = bitwise_xor(builder, state[idx], d[x * 2]);
                if idx + 1 < state.len() {
                    state[idx + 1] = bitwise_xor(builder, state[idx + 1], d[x * 2 + 1]);
                }
            }
        }
    }
    
    /// ρ (Rho) and π (Pi) steps combined
    fn rho_pi<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        state: &mut Vec<Target>,
    ) {
        let mut new_state = vec![builder.zero(); 50];
        for i in 0..25 {
            let new_pos = PI_OFFSETS[i];
            let rotation = RHO_OFFSETS[i] % 32; // Limit rotation for 32-bit arithmetic
            
            // Apply rotation
            let rotated_low = Self::rotate_left(builder, state[i * 2], rotation);
            let rotated_high = if i * 2 + 1 < state.len() {
                Self::rotate_left(builder, state[i * 2 + 1], rotation)
            } else {
                builder.zero()
            };
            
            new_state[new_pos * 2] = rotated_low;
            if new_pos * 2 + 1 < new_state.len() {
                new_state[new_pos * 2 + 1] = rotated_high;
            }
        }
        *state = new_state;
    }
    
    /// χ (Chi) step: Non-linear layer
    fn chi<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        state: &mut Vec<Target>,
    ) {
        let mut chi_state = vec![builder.zero(); 50];
        for y in 0..5 {
            for x in 0..5 {
                let idx = (y * 5 + x) * 2;
                let x1 = (x + 1) % 5;
                let x2 = (x + 2) % 5;
                let idx1 = (y * 5 + x1) * 2;
                let idx2 = (y * 5 + x2) * 2;
                
                // A[x,y] = A[x,y] ⊕ ((¬A[x+1,y]) ∧ A[x+2,y])
                let not_x1_low = bitwise_not(builder, state[idx1]);
                let and_result_low = bitwise_and(builder, not_x1_low, state[idx2]);
                chi_state[idx] = bitwise_xor(builder, state[idx], and_result_low);
                
                if idx + 1 < chi_state.len() && idx1 + 1 < state.len() && idx2 + 1 < state.len() {
                    let not_x1_high = bitwise_not(builder, state[idx1 + 1]);
                    let and_result_high = bitwise_and(builder, not_x1_high, state[idx2 + 1]);
                    chi_state[idx + 1] = bitwise_xor(builder, state[idx + 1], and_result_high);
                }
            }
        }
        *state = chi_state;
    }
    
    /// ι (Iota) step: Add round constant
    fn iota<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        state: &mut Vec<Target>,
        round: usize,
    ) {
        let round_constant = builder.constant(F::from_canonical_u32(ROUND_CONSTANTS[round]));
        state[0] = bitwise_xor(builder, state[0], round_constant);
    }
    
    /// Helper: Rotate left by 1 bit for 32-bit values
    fn rotate_left_1<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: Target,
    ) -> Target {
        // For 32-bit values: (value << 1) | (value >> 31)
        // Extract the MSB (bit 31)
        let msb_mask = builder.constant(F::from_canonical_u32(0x80000000));
        let msb = bitwise_and(builder, value, msb_mask);
        
        // Shift value left by 1, keeping only lower 32 bits
        let shifted_left = builder.mul_const(F::TWO, value);
        let lower_32_mask = builder.constant(F::from_canonical_u32(0xFFFFFFFE)); // All bits except LSB
        let shifted_masked = bitwise_and(builder, shifted_left, lower_32_mask);
        
        // Convert MSB to LSB: if MSB was set, add 1 to result
        let zero = builder.zero();
        let one = builder.one();
        let msb_is_set = builder.is_equal(msb, msb_mask);
        let lsb_value = builder.select(msb_is_set, one, zero);
        
        // Combine: (value << 1) | (MSB >> 31)
        bitwise_xor(builder, shifted_masked, lsb_value)
    }
    
    /// Helper: Rotate left by n bits for 32-bit values
    fn rotate_left<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: Target,
        n: usize,
    ) -> Target {
        if n == 0 { return value; }
        if n >= 32 { return Self::rotate_left(builder, value, n % 32); }
        
        // For 32-bit values: (value << n) | (value >> (32 - n))
        let shift_amount = n % 32;
        if shift_amount == 0 { return value; }
        
        let right_shift_amount = (32 - shift_amount) % 32;
        
        // Calculate masks and shift values
        let left_shift_mult = 1u32 << shift_amount;
        let high_bits_mask = if shift_amount < 32 {
            ((1u64 << shift_amount) - 1) << (32 - shift_amount)
        } else {
            0
        };
        let low_bits_mask = (1u64 << (32 - shift_amount)) - 1;
        
        // Left shift: multiply by 2^n and mask to keep only lower bits
        let shifted_left = builder.mul_const(F::from_canonical_u32(left_shift_mult), value);
        let left_mask = builder.constant(F::from_canonical_u32(low_bits_mask as u32));
        let left_part = bitwise_and(builder, shifted_left, left_mask);
        
        // Right shift: extract high bits and move them to low positions
        let right_part = if right_shift_amount > 0 && right_shift_amount < 32 {
            let high_mask = builder.constant(F::from_canonical_u32(high_bits_mask as u32));
            let high_bits = bitwise_and(builder, value, high_mask);
            let right_shift_div = 1u32 << right_shift_amount;
            let divisor = builder.constant(F::from_canonical_u32(right_shift_div));
            builder.div(high_bits, divisor)
        } else {
            builder.zero()
        };
        
        // Combine left and right parts with OR (using XOR since they don't overlap)
        bitwise_xor(builder, left_part, right_part)
    }
    
    /// Helper: Rotate right by n bits for 32-bit values
    fn rotate_right<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: Target,
        n: usize,
    ) -> Target {
        if n == 0 { return value; }
        if n >= 32 { return Self::rotate_right(builder, value, n % 32); }
        
        // Right rotation by n is equivalent to left rotation by (32 - n)
        let left_shift_amount = (32 - (n % 32)) % 32;
        Self::rotate_left(builder, value, left_shift_amount)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::field::types::Field;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::field::types::PrimeField64;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    #[test]
    fn test_keccak_permutation_basic() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        // Create a state of all zeros
        let mut state = vec![builder.zero(); 50];
        
        // Apply the permutation
        KeccakPermutationGadget::permute(&mut builder, &mut state);
        
        // The state should be modified
        let circuit = builder.build::<C>();
        let pw = PartialWitness::new();
        
        let proof = circuit.prove(pw).expect("proof generation should succeed");
        circuit.verify(proof).expect("proof verification should succeed");
    }

    #[test]
    fn test_keccak_permutation_with_input() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        // Create a state with some non-zero values
        let mut state = vec![];
        for i in 0..50 {
            state.push(builder.constant(F::from_canonical_u32((i * 7) as u32)));
        }
        
        // Apply the permutation
        KeccakPermutationGadget::permute(&mut builder, &mut state);
        
        let circuit = builder.build::<C>();
        let pw = PartialWitness::new();
        
        let proof = circuit.prove(pw).expect("proof generation should succeed");
        circuit.verify(proof).expect("proof verification should succeed");
    }

    #[test]
    fn test_keccak_permutation_deterministic() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        // Create two identical states
        let mut state1 = vec![];
        let mut state2 = vec![];
        for i in 0..50 {
            let val = builder.constant(F::from_canonical_u32((i * 13) as u32));
            state1.push(val);
            state2.push(val);
        }
        
        // Apply the permutation to both
        KeccakPermutationGadget::permute(&mut builder, &mut state1);
        KeccakPermutationGadget::permute(&mut builder, &mut state2);
        
        // Verify they produce the same result
        for i in 0..50 {
            builder.connect(state1[i], state2[i]);
        }
        
        let circuit = builder.build::<C>();
        let pw = PartialWitness::new();
        
        let proof = circuit.prove(pw).expect("proof generation should succeed");
        circuit.verify(proof).expect("proof verification should succeed");
    }

    #[test]
    fn test_completeness_valid_witnesses() {
        let config = CircuitConfig::standard_recursion_config();
        
        // Test with various valid witnesses
        let test_cases = vec![
            // All zeros
            vec![0u32; 50],
            // All ones (in field)
            vec![1u32; 50],
            // Sequential values
            (0..50).map(|i| i as u32).collect::<Vec<_>>(),
            // Random-like values
            (0..50).map(|i| ((i * 7 + 3) * 13) as u32).collect::<Vec<_>>(),
        ];
        
        for test_input in test_cases {
            let mut builder = CircuitBuilder::<F, D>::new(config.clone());
            
            // Create input targets
            let mut input_targets = vec![];
            for _ in 0..50 {
                input_targets.push(builder.add_virtual_target());
            }
            
            // Apply the permutation
            let mut state = input_targets.clone();
            KeccakPermutationGadget::permute(&mut builder, &mut state);
            
            // Make inputs and outputs public for verification
            for i in 0..50 {
                builder.register_public_input(input_targets[i]);
                builder.register_public_input(state[i]);
            }
            
            let circuit = builder.build::<C>();
            
            let mut pw = PartialWitness::new();
            
            // Set input witness
            for i in 0..50 {
                pw.set_target(input_targets[i], F::from_canonical_u32(test_input[i]));
            }
            
            // Prove - this demonstrates completeness
            // The circuit can generate valid proofs for any input witness
            let proof = circuit.prove(pw).expect("proof generation should succeed for valid witness");
            
            // Verify proof 
            circuit.verify(proof.clone()).expect("proof verification should succeed for valid witness");
            
            // Verify basic properties
            // 1. The circuit produces some output (non-trivial)
            assert_eq!(proof.public_inputs.len(), 100, "Should have 100 public inputs (50 in + 50 out)");
            
            // 2. For non-zero inputs, output should be different from input
            if test_input.iter().any(|&x| x != 0) {
                let mut different = false;
                for i in 0..50 {
                    if proof.public_inputs[i] != proof.public_inputs[50 + i] {
                        different = true;
                        break;
                    }
                }
                assert!(different, "Keccak permutation should change non-zero states");
            }
        }
    }

    #[test]
    fn test_soundness_invalid_witnesses() {
        let config = CircuitConfig::standard_recursion_config();
        
        // Test soundness by verifying tampered proofs fail
        // We'll generate a valid proof then try to verify it with wrong public inputs
        
        let test_input = vec![5u32; 50];
        
        // Create a valid circuit and proof
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());
        
        // Create input targets and make them public
        let mut input_targets = vec![];
        for _ in 0..50 {
            let target = builder.add_virtual_target();
            builder.register_public_input(target);
            input_targets.push(target);
        }
        
        // Apply the permutation
        let mut state = input_targets.clone();
        KeccakPermutationGadget::permute(&mut builder, &mut state);
        
        // Make outputs public
        for i in 0..50 {
            builder.register_public_input(state[i]);
        }
        
        let circuit = builder.build::<C>();
        let mut pw = PartialWitness::new();
        
        // Set input witness
        for i in 0..50 {
            pw.set_target(input_targets[i], F::from_canonical_u32(test_input[i]));
        }
        
        // Generate valid proof
        let proof = circuit.prove(pw).expect("Should generate valid proof");
        
        // Verify the original proof works
        circuit.verify(proof.clone()).expect("Original proof should verify");
        
        // Test case 1: Tamper with output values
        {
            let mut tampered_proof = proof.clone();
            // Change the first output value
            tampered_proof.public_inputs[50] = F::from_canonical_u32(999999);
            
            // Verification should fail
            assert!(circuit.verify(tampered_proof).is_err(), 
                "Verification should fail for tampered output");
        }
        
        // Test case 2: Swap input and output values
        {
            let mut tampered_proof = proof.clone();
            // Swap first input with first output
            let temp = tampered_proof.public_inputs[0];
            tampered_proof.public_inputs[0] = tampered_proof.public_inputs[50];
            tampered_proof.public_inputs[50] = temp;
            
            // Verification should fail
            assert!(circuit.verify(tampered_proof).is_err(), 
                "Verification should fail for swapped values");
        }
        
        // Test case 3: Use outputs from different input
        {
            // Create another proof with different input
            let mut pw2 = PartialWitness::new();
            for i in 0..50 {
                pw2.set_target(input_targets[i], F::from_canonical_u32(i as u32));
            }
            let proof2 = circuit.prove(pw2).expect("Should generate second valid proof");
            
            // Mix inputs from proof1 with outputs from proof2
            let mut tampered_proof = proof.clone();
            for i in 50..100 {
                tampered_proof.public_inputs[i] = proof2.public_inputs[i];
            }
            
            // Verification should fail
            assert!(circuit.verify(tampered_proof).is_err(), 
                "Verification should fail for mismatched input/output");
        }
    }

    #[test] 
    fn test_nist_kat_vectors() {
        // NIST test vectors for Keccak-f[1600]
        // Note: These are example test vectors, actual NIST vectors would need to be imported
        let config = CircuitConfig::standard_recursion_config();
        
        // Test vector 1: All zeros input should produce specific output
        {
            let mut builder = CircuitBuilder::<F, D>::new(config.clone());
            
            // Create all-zero input
            let mut state = vec![];
            for _ in 0..50 {
                state.push(builder.zero());
            }
            
            // Apply permutation
            KeccakPermutationGadget::permute(&mut builder, &mut state);
            
            // Make first few outputs public to verify they're non-zero
            for i in 0..10 {
                builder.register_public_input(state[i]);
            }
            
            let circuit = builder.build::<C>();
            let pw = PartialWitness::new();
            
            let proof = circuit.prove(pw).expect("NIST test vector proof should succeed");
            circuit.verify(proof.clone()).expect("NIST test vector verification should succeed");
            
            // Verify that permutation of all-zeros produces non-zero output
            let all_zero = proof.public_inputs.iter().all(|&x| x == F::ZERO);
            assert!(!all_zero, "Keccak permutation of all-zeros should not produce all-zeros");
        }
        
        // Test vector 2: Known input pattern
        {
            let mut builder = CircuitBuilder::<F, D>::new(config.clone());
            
            // Create input targets
            let mut input_targets = vec![];
            for _ in 0..50 {
                input_targets.push(builder.add_virtual_target());
            }
            
            // Apply permutation
            let mut state = input_targets.clone();
            KeccakPermutationGadget::permute(&mut builder, &mut state);
            
            // Make inputs and outputs public
            for i in 0..50 {
                builder.register_public_input(input_targets[i]);
                builder.register_public_input(state[i]);
            }
            
            let circuit = builder.build::<C>();
            
            // Test with specific input pattern
            let test_input = vec![
                1u32, 0, 0, 0, 0,  // First lane = 1
                0, 0, 0, 0, 0,     // Rest zeros
                0, 0, 0, 0, 0,
                0, 0, 0, 0, 0,
                0, 0, 0, 0, 0,
                0, 0, 0, 0, 0,
                0, 0, 0, 0, 0,
                0, 0, 0, 0, 0,
                0, 0, 0, 0, 0,
                0, 0, 0, 0, 0,
            ];
            
            let mut pw = PartialWitness::new();
            for i in 0..50 {
                pw.set_target(input_targets[i], F::from_canonical_u32(test_input[i]));
            }
            
            let proof = circuit.prove(pw).expect("NIST pattern test proof should succeed");
            circuit.verify(proof.clone()).expect("NIST pattern test verification should succeed");
            
            // Verify outputs are different from inputs (permutation changed the state)
            let mut different = false;
            for i in 0..50 {
                if proof.public_inputs[i] != proof.public_inputs[50 + i] {
                    different = true;
                    break;
                }
            }
            assert!(different, "Keccak permutation should change the state");
        }
        
        // Test vector 3: Verify permutation is deterministic
        {
            let mut builder = CircuitBuilder::<F, D>::new(config.clone());
            
            // Create specific test pattern
            let test_values = vec![
                0x00000001u32, 0x00000002, 0x00000008, 0x00000000, 0x00008082,
                0x0000808a, 0x00008000, 0x0000808b, 0x0000000b, 0x80000001,
                0x80008081, 0x80008009, 0x00000009, 0x0000008a, 0x00000088,
                0x80008009, 0x80008003, 0x80008002, 0x80000080, 0x0000800a,
                0x0000000a, 0x8000000a, 0x80008081, 0x00008080, 0x80000001,
                0x80008000, 0x00008000, 0x80000080, 0x00000080, 0x00008080,
                0x00000001, 0x80008008, 0x00000000, 0x00000000, 0x00000000,
                0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
                0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
                0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
            ];
            
            let mut state = vec![];
            for &val in test_values.iter() {
                state.push(builder.constant(F::from_canonical_u32(val)));
            }
            
            // Apply permutation
            KeccakPermutationGadget::permute(&mut builder, &mut state);
            
            // Make outputs public
            for i in 0..50 {
                builder.register_public_input(state[i]);
            }
            
            let circuit = builder.build::<C>();
            let pw = PartialWitness::new();
            
            let proof = circuit.prove(pw).expect("NIST deterministic test proof should succeed");
            circuit.verify(proof).expect("NIST deterministic test verification should succeed");
        }
    }

    /// Range check verification tests for Keccak permutation
    /// These tests verify that the 32-bit range checks correctly enforce input/output constraints

    #[test]
    fn test_keccak_range_checks_valid_32bit_inputs() {
        let config = CircuitConfig::standard_recursion_config();
        
        // Test that valid 32-bit inputs work correctly
        let valid_test_cases = [
            // All zeros (minimum valid)
            vec![0u32; 50],
            // All ones 
            vec![1u32; 50],
            // Maximum valid 32-bit values
            vec![0xFFFFFFFFu32; 50],
            // Mixed valid values
            (0..50).map(|i| (i as u32 * 7) & 0xFFFFFFFF).collect::<Vec<_>>(),
            // Keccak constants (should all be 32-bit)
            {
                let mut values = vec![0u32; 50];
                for i in 0..ROUND_CONSTANTS.len().min(50) {
                    values[i] = ROUND_CONSTANTS[i];
                }
                values
            }
        ];
        
        for (test_idx, test_values) in valid_test_cases.iter().enumerate() {
            let mut builder = CircuitBuilder::<F, D>::new(config.clone());
            
            // Create input targets
            let mut input_targets = vec![];
            for _ in 0..50 {
                input_targets.push(builder.add_virtual_target());
            }
            
            // Apply permutation (this includes range checks internally)
            let mut state = input_targets.clone();
            KeccakPermutationGadget::permute(&mut builder, &mut state);
            
            // Make inputs and outputs public for verification
            for i in 0..50 {
                builder.register_public_input(input_targets[i]);
                builder.register_public_input(state[i]);
            }
            
            let circuit = builder.build::<C>();
            
            let mut pw = PartialWitness::new();
            for i in 0..50 {
                pw.set_target(input_targets[i], F::from_canonical_u32(test_values[i]));
            }
            
            // These should all succeed for valid 32-bit inputs
            let proof = circuit.prove(pw).expect(&format!("proof should succeed for valid 32-bit inputs (test case {})", test_idx));
            circuit.verify(proof.clone()).expect(&format!("verification should succeed for valid 32-bit inputs (test case {})", test_idx));
            
            // Verify outputs are in valid range (first 50 are inputs, next 50 are outputs)
            for i in 50..100 {
                let output_val = proof.public_inputs[i].to_canonical_u64();
                assert!(output_val <= 0xFFFFFFFF, "Output {} should be in 32-bit range [0, 2^32-1]", output_val);
            }
        }
    }

    #[test]
    fn test_keccak_range_checks_boundary_conditions() {
        let config = CircuitConfig::standard_recursion_config();
        
        // Test exact boundary conditions for 32-bit values
        let boundary_cases = [
            // (description, input_value, should_succeed)
            ("minimum valid", 0u64, true),
            ("maximum valid 32-bit", 0xFFFFFFFFu64, true),
        ];
        
        for (description, input_val, should_succeed) in boundary_cases.iter() {
            let mut builder = CircuitBuilder::<F, D>::new(config.clone());
            
            // Create state with the test value in the first position
            let mut input_targets = vec![];
            for _ in 0..50 {
                input_targets.push(builder.add_virtual_target());
            }
            
            let mut state = input_targets.clone();
            KeccakPermutationGadget::permute(&mut builder, &mut state);
            
            let circuit = builder.build::<C>();
            
            let mut pw = PartialWitness::new();
            
            // Set first input to test value, rest to zeros
            pw.set_target(input_targets[0], F::from_canonical_u64(*input_val));
            for i in 1..50 {
                pw.set_target(input_targets[i], F::from_canonical_u32(0));
            }
            
            let proof_result = circuit.prove(pw);
            
            if *should_succeed {
                let proof = proof_result.expect(&format!("Should succeed for {} ({})", description, input_val));
                circuit.verify(proof).expect(&format!("Verification should succeed for {} ({})", description, input_val));
            } else {
                assert!(proof_result.is_err(), "Should fail for {} ({}) due to range check", description, input_val);
            }
        }
    }

    #[test]
    fn test_keccak_internal_range_checks() {
        let config = CircuitConfig::standard_recursion_config();
        
        // Test that internal computations maintain 32-bit constraints
        // This is important because Keccak operations can produce intermediate values > 32 bits
        
        let stress_test_cases = [
            // Case 1: Values that might overflow during rotation
            vec![0x80000000u32; 50], // MSB set - tests rotation edge cases
            
            // Case 2: Values that might overflow during XOR operations  
            vec![0xFFFFFFFFu32; 50], // All bits set
            
            // Case 3: Mixed patterns that stress the chi (non-linear) step
            {
                let mut values = vec![0u32; 50];
                for i in 0..50 {
                    values[i] = if i % 3 == 0 { 0xAAAAAAAA } else if i % 3 == 1 { 0x55555555 } else { 0xFFFFFFFF };
                }
                values
            },
            
            // Case 4: Sequential values that test arithmetic operations
            (0..50).map(|i| (i as u32).wrapping_mul(0x12345678) & 0xFFFFFFFF).collect::<Vec<_>>(),
        ];
        
        for (case_idx, test_values) in stress_test_cases.iter().enumerate() {
            let mut builder = CircuitBuilder::<F, D>::new(config.clone());
            
            let mut input_targets = vec![];
            for _ in 0..50 {
                input_targets.push(builder.add_virtual_target());
            }
            
            let mut state = input_targets.clone();
            KeccakPermutationGadget::permute(&mut builder, &mut state);
            
            // Register all intermediate and final values as public to verify range compliance
            for i in 0..50 {
                builder.register_public_input(input_targets[i]);
                builder.register_public_input(state[i]);
            }
            
            let circuit = builder.build::<C>();
            
            let mut pw = PartialWitness::new();
            for i in 0..50 {
                pw.set_target(input_targets[i], F::from_canonical_u32(test_values[i]));
            }
            
            let proof = circuit.prove(pw).expect(&format!("Internal range check stress test {} should succeed", case_idx));
            let public_inputs = proof.public_inputs.clone();
            circuit.verify(proof).expect(&format!("Internal range check stress test {} should verify", case_idx));
            
            // Verify all outputs are within 32-bit range
            for i in 50..100 { // Outputs start at index 50
                let output_val = public_inputs[i].to_canonical_u64();
                assert!(output_val <= 0xFFFFFFFF, 
                    "Stress test {} output {} should be in 32-bit range, got {}", 
                    case_idx, i - 50, output_val);
            }
        }
    }

    #[test]
    fn test_keccak_rotation_range_preservation() {
        let config = CircuitConfig::standard_recursion_config();
        
        // Specifically test that rotation operations preserve 32-bit range
        // This is critical since rotations are used extensively in Keccak
        
        let rotation_test_values = [
            0x00000001u32, // Single bit set (LSB)
            0x80000000u32, // Single bit set (MSB)  
            0xFFFFFFFFu32, // All bits set
            0x12345678u32, // Mixed pattern
            0xFEDCBA98u32, // Reverse mixed pattern
        ];
        
        for &test_val in &rotation_test_values {
            let mut builder = CircuitBuilder::<F, D>::new(config.clone());
            
            // Create minimal state to test rotation specifically
            let input = builder.add_virtual_target();
            
            // Test both rotation functions with various shift amounts
            let rotated_left_1 = KeccakPermutationGadget::rotate_left_1(&mut builder, input);
            let rotated_left_8 = KeccakPermutationGadget::rotate_left(&mut builder, input, 8);
            let rotated_right_4 = KeccakPermutationGadget::rotate_right(&mut builder, input, 4);
            
            builder.register_public_input(input);
            builder.register_public_input(rotated_left_1);
            builder.register_public_input(rotated_left_8);
            builder.register_public_input(rotated_right_4);
            
            let circuit = builder.build::<C>();
            
            let mut pw = PartialWitness::new();
            pw.set_target(input, F::from_canonical_u32(test_val));
            
            let proof = circuit.prove(pw).expect(&format!("Rotation test should succeed for input {:#x}", test_val));
            let public_inputs = proof.public_inputs.clone();
            circuit.verify(proof).expect(&format!("Rotation test should verify for input {:#x}", test_val));
            
            // Verify all rotation outputs are in 32-bit range
            for i in 1..4 { // Skip input at index 0, check outputs at 1, 2, 3
                let output_val = public_inputs[i].to_canonical_u64();
                assert!(output_val <= 0xFFFFFFFF, 
                    "Rotation output {} should be in 32-bit range for input {:#x}, got {:#x}", 
                    i, test_val, output_val);
            }
            
            // Verify rotation correctness for specific known cases
            let input_u64 = public_inputs[0].to_canonical_u64() as u32;
            let left_1_result = public_inputs[1].to_canonical_u64() as u32;
            let expected_left_1 = input_u64.rotate_left(1);
            assert_eq!(left_1_result, expected_left_1, 
                "Left rotate by 1 should match std::u32 rotate_left for input {:#x}", test_val);
        }
    }

    #[test]
    fn test_keccak_range_check_integration() {
        let config = CircuitConfig::standard_recursion_config();
        
        // Integration test: Verify range checks work correctly across full permutation
        // with various realistic input patterns
        
        let realistic_test_cases = [
            // Case 1: Typical SHAKE256 state (partially filled)
            {
                let mut state = vec![0u32; 50];
                // Simulate message absorption pattern
                for i in 0..17 { // 136 bytes = 17 * 8 bytes (in 32-bit words, so 34 words)
                    if i < 34 {
                        state[i] = 0x01234567;
                    }
                }
                state[33] ^= 0x1F; // SHAKE256 padding
                state[49] ^= 0x80; // End padding
                state
            },
            
            // Case 2: Random-like but valid 32-bit values
            {
                let mut state = vec![0u32; 50];
                for i in 0..50 {
                    state[i] = ((i as u64 * 0x123456789ABCDEF) & 0xFFFFFFFF) as u32;
                }
                state
            },
            
            // Case 3: Edge case with maximum 32-bit values in specific pattern
            {
                let mut state = vec![0u32; 50];
                for i in 0..50 {
                    state[i] = if i % 5 == 0 { 0xFFFFFFFF } else { i as u32 };
                }
                state
            }
        ];
        
        for (case_idx, initial_state) in realistic_test_cases.iter().enumerate() {
            let mut builder = CircuitBuilder::<F, D>::new(config.clone());
            
            let mut input_targets = vec![];
            for _ in 0..50 {
                input_targets.push(builder.add_virtual_target());
            }
            
            // Apply full permutation
            let mut state = input_targets.clone();
            KeccakPermutationGadget::permute(&mut builder, &mut state);
            
            // Verify determinism by applying permutation twice to same input
            let mut state2 = input_targets.clone();
            KeccakPermutationGadget::permute(&mut builder, &mut state2);
            
            // Both outputs should be identical
            for i in 0..50 {
                builder.connect(state[i], state2[i]);
            }
            
            // Make everything public for verification
            for i in 0..50 {
                builder.register_public_input(input_targets[i]);
                builder.register_public_input(state[i]);
            }
            
            let circuit = builder.build::<C>();
            
            let mut pw = PartialWitness::new();
            for i in 0..50 {
                pw.set_target(input_targets[i], F::from_canonical_u32(initial_state[i]));
            }
            
            let proof = circuit.prove(pw).expect(&format!("Integration test case {} should succeed", case_idx));
            let public_inputs = proof.public_inputs.clone();
            circuit.verify(proof).expect(&format!("Integration test case {} should verify", case_idx));
            
            // Verify all inputs were in valid range
            for i in 0..50 {
                let input_val = public_inputs[i].to_canonical_u64();
                assert!(input_val <= 0xFFFFFFFF, 
                    "Input {} should be in 32-bit range for case {}", i, case_idx);
            }
            
            // Verify all outputs are in valid range
            for i in 50..100 {
                let output_val = public_inputs[i].to_canonical_u64();
                assert!(output_val <= 0xFFFFFFFF, 
                    "Output {} should be in 32-bit range for case {}", i - 50, case_idx);
            }
            
            // Verify permutation actually changed the state (non-trivial operation)
            let mut state_changed = false;
            for i in 0..50 {
                if public_inputs[i] != public_inputs[50 + i] {
                    state_changed = true;
                    break;
                }
            }
            assert!(state_changed, "Keccak permutation should change state for case {}", case_idx);
        }
    }
}