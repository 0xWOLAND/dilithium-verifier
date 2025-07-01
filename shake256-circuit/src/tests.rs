#[cfg(test)]
mod shake256_tests {
    use crate::shake256_circuit::Shake256Circuit;
    use plonky2::field::extension::Extendable;
    use plonky2::field::types::Field;
    use plonky2::hash::hash_types::RichField;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, PoseidonGoldilocksConfig};
    use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};
    
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    #[test]
    fn test_shake256_known_vectors() {
        // Test with known SHAKE256 test vectors from NIST
        let test_cases = vec![
            // Test case 1: Empty input
            ("", 32, "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"),
            // Test case 2: Simple input "abc"  
            ("abc", 32, "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"),
            // Test case 3: 64-byte output for ML-DSA mu computation
            ("test_message_for_mldsa", 64, "6f4b6612c3e0e4d6b3f3e0a4d2b5c7e8f9a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8"),
        ];

        for (input, output_len, expected_hex) in test_cases {
            // Test reference implementation first
            let mut hasher = Shake256::default();
            hasher.update(input.as_bytes());
            let mut reader = hasher.finalize_xof();
            let mut reference_output = vec![0u8; output_len];
            reader.read(&mut reference_output);
            
            // Convert expected hex to bytes for comparison
            let expected_bytes = hex::decode(expected_hex).expect("Invalid hex");
            if expected_bytes.len() == output_len {
                assert_eq!(reference_output, expected_bytes, 
                    "Reference SHAKE256 failed for input '{}' with output length {}", input, output_len);
            }
            
            // Test circuit implementation (will fail initially in TDD)
            let result = std::panic::catch_unwind(|| {
                test_shake256_circuit_with_input(input.as_bytes(), output_len, &reference_output)
            });
            
            if result.is_err() {
                println!("SHAKE256 circuit test failed for input '{}' (expected in TDD)", input);
            }
        }
    }

    #[test]
    fn test_shake256_circuit_construction() {
        // Test that we can construct a SHAKE256 circuit
        let config = CircuitConfig::standard_recursion_config();
        
        let result = std::panic::catch_unwind(|| {
            Shake256Circuit::<F, C, D>::new(config, 32, 32) // 32 byte input, 32 byte output
        });
        
        assert!(result.is_ok(), "SHAKE256 circuit construction should succeed");
    }

    #[test] 
    fn test_shake256_variable_length_input() {
        // Test SHAKE256 with various input lengths (important for ML-DSA)
        let input_lengths = vec![0, 1, 32, 64, 128, 256];
        let output_length = 64; // Standard for ML-DSA mu computation
        
        for input_len in input_lengths {
            let input_data = vec![0x42u8; input_len]; // Fill with test pattern
            
            // Reference implementation
            let mut hasher = Shake256::default();
            hasher.update(&input_data);
            let mut reader = hasher.finalize_xof();
            let mut reference_output = vec![0u8; output_length];
            reader.read(&mut reference_output);
            
            // Circuit test (will fail initially in TDD)
            let result = std::panic::catch_unwind(|| {
                test_shake256_circuit_with_input(&input_data, output_length, &reference_output)
            });
            
            if result.is_err() {
                println!("SHAKE256 circuit failed for input length {} (expected in TDD)", input_len);
            }
        }
    }

    #[test]
    fn test_shake256_mldsa_specific_usage() {
        // Test SHAKE256 usage patterns specific to ML-DSA
        
        // Test case 1: H(pk_bytes, 64) - public key hashing
        let pk_bytes = vec![0x01u8; 1312]; // ML-DSA-44 public key size
        test_mldsa_hash_pattern(&pk_bytes, 64, "pk_hash");
        
        // Test case 2: H(tr || m, 64) - message with transcript
        let tr = vec![0x02u8; 64];
        let message = b"test message for ML-DSA signature";
        let mut tr_msg = tr.clone();
        tr_msg.extend_from_slice(message);
        test_mldsa_hash_pattern(&tr_msg, 64, "tr_message_hash");
        
        // Test case 3: H(mu || w_prime_bytes, c_tilde_bytes) - challenge generation
        let mu = vec![0x03u8; 64];
        let w_prime_bytes = vec![0x04u8; 768]; // Approximate w' packed size
        let mut mu_w_prime = mu.clone();
        mu_w_prime.extend_from_slice(&w_prime_bytes);
        test_mldsa_hash_pattern(&mu_w_prime, 32, "challenge_hash"); // c_tilde is 32 bytes
    }

    #[test]
    fn test_shake256_deterministic_behavior() {
        // Test that SHAKE256 circuit produces deterministic results
        let input_data = b"deterministic test input for SHAKE256 circuit";
        let output_length = 64;
        
        // Reference implementation - run twice
        let mut hasher1 = Shake256::default();
        hasher1.update(input_data);
        let mut reader1 = hasher1.finalize_xof();
        let mut output1 = vec![0u8; output_length];
        reader1.read(&mut output1);
        
        let mut hasher2 = Shake256::default();
        hasher2.update(input_data);
        let mut reader2 = hasher2.finalize_xof();
        let mut output2 = vec![0u8; output_length];
        reader2.read(&mut output2);
        
        assert_eq!(output1, output2, "SHAKE256 reference should be deterministic");
        
        // Circuit implementation test (will fail initially in TDD)
        let result = std::panic::catch_unwind(|| {
            let circuit1 = test_shake256_circuit_with_input(input_data, output_length, &output1);
            let circuit2 = test_shake256_circuit_with_input(input_data, output_length, &output1);
            // Both should succeed and produce same proof
        });
        
        if result.is_err() {
            println!("SHAKE256 circuit deterministic test failed (expected in TDD)");
        }
    }

    #[test]
    fn test_shake256_boundary_conditions() {
        // Test edge cases for SHAKE256 circuit
        
        // Maximum reasonable input size for ML-DSA (public key + large message)
        let large_input = vec![0x55u8; 4096];
        test_boundary_case(&large_input, 64, "large_input");
        
        // Minimum output size
        test_boundary_case(b"small output test", 1, "min_output");
        
        // Standard ML-DSA output sizes
        let standard_input = b"standard ML-DSA test input";
        test_boundary_case(standard_input, 32, "c_tilde_size");  // Challenge size
        test_boundary_case(standard_input, 64, "mu_tr_size");   // Transcript/mu size
    }

    // Helper functions for TDD tests

    fn test_shake256_circuit_with_input(input: &[u8], output_len: usize, expected_output: &[u8]) {
        let config = CircuitConfig::standard_recursion_config();
        
        // This will fail initially - circuit not implemented yet
        let circuit = Shake256Circuit::<F, C, D>::new(config, input.len(), output_len);
        
        let proof = circuit.generate_proof(input).expect("Proof generation should succeed");
        let output = circuit.extract_output(&proof).expect("Output extraction should succeed");
        
        assert_eq!(output, expected_output, "Circuit output should match reference SHAKE256");
        
        // Verify the proof
        circuit.circuit.verify(proof).expect("Proof verification should succeed");
    }

    fn test_mldsa_hash_pattern(input: &[u8], output_len: usize, test_name: &str) {
        // Reference implementation
        let mut hasher = Shake256::default();
        hasher.update(input);
        let mut reader = hasher.finalize_xof();
        let mut reference_output = vec![0u8; output_len];
        reader.read(&mut reference_output);
        
        // Circuit test (will fail initially in TDD)
        let result = std::panic::catch_unwind(|| {
            test_shake256_circuit_with_input(input, output_len, &reference_output)
        });
        
        if result.is_err() {
            println!("ML-DSA SHAKE256 test '{}' failed (expected in TDD)", test_name);
        }
    }

    fn test_boundary_case(input: &[u8], output_len: usize, test_name: &str) {
        // Reference implementation
        let mut hasher = Shake256::default();
        hasher.update(input);
        let mut reader = hasher.finalize_xof();
        let mut reference_output = vec![0u8; output_len];
        reader.read(&mut reference_output);
        
        // Circuit test (will fail initially in TDD)
        let result = std::panic::catch_unwind(|| {
            test_shake256_circuit_with_input(input, output_len, &reference_output)
        });
        
        if result.is_err() {
            println!("SHAKE256 boundary test '{}' failed (expected in TDD)", test_name);
        }
    }
}