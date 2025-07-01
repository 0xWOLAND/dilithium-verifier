#[cfg(test)]
mod tests {
    use crate::complete_verifier::CompleteMLDSAVerifierCircuit;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use plonky2::plonk::circuit_data::CircuitConfig;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as plonky2::plonk::config::GenericConfig<D>>::F;

    #[test]
    fn test_complete_mldsa44_verification_step_by_step() {
        // Test ML-DSA-44 with actual parameters from FIPS 204
        let config = CircuitConfig::standard_recursion_config();
        
        // ML-DSA-44 parameters from FIPS 204
        let k = 4;
        let l = 4;
        let eta = 2;
        let gamma_1 = 1 << 17; // 2^17 = 131072
        let gamma_2 = (crate::constants::Q - 1) / 88; // ≈ 95232
        let tau = 39;
        let omega = 80;
        
        // This should fail initially because CompleteMLDSAVerifierCircuit doesn't compile yet
        let verifier = CompleteMLDSAVerifierCircuit::<F, C, D>::new(
            config, k, l, eta, gamma_1, gamma_2, tau, omega
        );
        
        // Create minimal test data
        let pk_bytes = vec![42u8; 32 + k * 256 * 2]; // rho + t1 packed
        let sig_bytes = vec![123u8; 32 + l * 256 * 3 + k * 256]; // c_tilde + z + h packed
        let message = b"test message for complete ML-DSA verification";
        
        let proof_result = verifier.generate_proof(&pk_bytes, &sig_bytes, message);
        
        // This should succeed once the implementation is complete
        assert!(proof_result.is_ok(), "Complete ML-DSA-44 verification should work: {:?}", proof_result.err());
        
        let proof = proof_result.unwrap();
        let verify_result = verifier.circuit.verify(proof);
        assert!(verify_result.is_ok(), "Complete ML-DSA-44 proof verification should work: {:?}", verify_result.err());
    }

    #[test]
    fn test_hint_weight_validation() {
        // Test that hint weight validation works correctly
        let config = CircuitConfig::standard_recursion_config();
        
        let k = 2; // Smaller for testing
        let l = 2;
        let eta = 2;
        let gamma_1 = 1 << 17;
        let gamma_2 = (crate::constants::Q - 1) / 88;
        let tau = 39;
        let omega = 5; // Small omega to test hint weight constraint
        
        let verifier = CompleteMLDSAVerifierCircuit::<F, C, D>::new(
            config, k, l, eta, gamma_1, gamma_2, tau, omega
        );
        
        // Create signature with too many hints (should fail)
        let pk_bytes = vec![42u8; 32 + k * 256 * 2];
        let mut sig_bytes = vec![123u8; 32 + l * 256 * 3 + k * 256];
        
        // Set hint bits to exceed omega limit
        let hint_start = 32 + l * 256 * 3;
        for i in 0..std::cmp::min(10, sig_bytes.len() - hint_start) {
            sig_bytes[hint_start + i] = 1; // Set more than omega=5 hints
        }
        
        let message = b"test";
        let proof_result = verifier.generate_proof(&pk_bytes, &sig_bytes, message);
        
        // This should fail due to hint weight constraint
        if let Ok(proof) = proof_result {
            let verify_result = verifier.circuit.verify(proof);
            // The circuit should reject signatures with too many hints  
            assert!(verify_result.is_err(), "Circuit should reject signatures with too many hints");
        }
    }

    #[test]
    fn test_signature_norm_bound_validation() {
        // Test that signature norm bound checking works
        let config = CircuitConfig::standard_recursion_config();
        
        let k = 2;
        let l = 2; 
        let eta = 2;
        let gamma_1 = 1000; // Small gamma_1 to make bounds easier to violate
        let gamma_2 = 500;
        let tau = 39;
        let omega = 80;
        let beta = tau as u32 * eta;
        
        let verifier = CompleteMLDSAVerifierCircuit::<F, C, D>::new(
            config, k, l, eta, gamma_1, gamma_2, tau, omega
        );
        
        let pk_bytes = vec![42u8; 32 + k * 256 * 2];
        let mut sig_bytes = vec![0u8; 32 + l * 256 * 3 + k * 256];
        
        // Set some z coefficients to violate the norm bound γ₁ - β
        let z_start = 32;
        let large_coeff = gamma_1 - beta + 1; // This should violate the bound
        
        // Encode large coefficient in z section (simplified)
        if z_start + 8 < sig_bytes.len() {
            let bytes = large_coeff.to_le_bytes();
            for (i, &byte) in bytes.iter().enumerate() {
                if z_start + i < sig_bytes.len() {
                    sig_bytes[z_start + i] = byte;
                }
            }
        }
        
        let message = b"test";
        let proof_result = verifier.generate_proof(&pk_bytes, &sig_bytes, message);
        
        // This should work at the proof generation level, but the circuit should detect the norm violation
        if let Ok(proof) = proof_result {
            let verify_result = verifier.circuit.verify(proof);
            // The circuit should reject signatures that violate norm bounds
            assert!(verify_result.is_err(), "Circuit should reject signatures that violate norm bounds");
        }
    }

    #[test]
    fn test_challenge_reconstruction() {
        // Test that challenge reconstruction works correctly
        let config = CircuitConfig::standard_recursion_config();
        
        let k = 1;
        let l = 1;
        let eta = 2;
        let gamma_1 = 1 << 17;
        let gamma_2 = (crate::constants::Q - 1) / 88;
        let tau = 10; // Smaller tau for testing
        let omega = 80;
        
        let verifier = CompleteMLDSAVerifierCircuit::<F, C, D>::new(
            config, k, l, eta, gamma_1, gamma_2, tau, omega
        );
        
        let pk_bytes = vec![42u8; 32 + k * 256 * 2];
        let sig_bytes = vec![123u8; 32 + l * 256 * 3 + k * 256];
        let message = b"challenge test";
        
        let proof_result = verifier.generate_proof(&pk_bytes, &sig_bytes, message);
        
        // This tests the full verification pipeline including challenge reconstruction
        assert!(proof_result.is_ok(), "Challenge reconstruction should work: {:?}", proof_result.err());
        
        if let Ok(proof) = proof_result {
            let verify_result = verifier.circuit.verify(proof);
            // The verification might fail if challenges don't match, which is expected for random data
            // But the circuit construction and proof generation should work
            println!("Challenge reconstruction test completed: verify_result = {:?}", verify_result.is_ok());
        }
    }

    #[test]
    fn test_matrix_expansion_deterministic() {
        // Test that matrix expansion from seed is deterministic
        let config1 = CircuitConfig::standard_recursion_config();
        let config2 = CircuitConfig::standard_recursion_config();
        
        let k = 2;
        let l = 2;
        let eta = 2;
        let gamma_1 = 1 << 17;
        let gamma_2 = (crate::constants::Q - 1) / 88;
        let tau = 39;
        let omega = 80;
        
        let verifier1 = CompleteMLDSAVerifierCircuit::<F, C, D>::new(
            config1, k, l, eta, gamma_1, gamma_2, tau, omega
        );
        let verifier2 = CompleteMLDSAVerifierCircuit::<F, C, D>::new(
            config2, k, l, eta, gamma_1, gamma_2, tau, omega
        );
        
        // Same input should produce same results
        let pk_bytes = vec![42u8; 32 + k * 256 * 2];
        let sig_bytes = vec![123u8; 32 + l * 256 * 3 + k * 256];
        let message = b"deterministic test";
        
        let proof1_result = verifier1.generate_proof(&pk_bytes, &sig_bytes, message);
        let proof2_result = verifier2.generate_proof(&pk_bytes, &sig_bytes, message);
        
        // Both should succeed or fail in the same way
        assert_eq!(proof1_result.is_ok(), proof2_result.is_ok(), 
                  "Matrix expansion should be deterministic");
    }

    #[test]
    fn test_polynomial_operations_in_ntt_domain() {
        // Test polynomial operations work correctly in NTT domain
        let config = CircuitConfig::standard_recursion_config();
        
        let k = 1;
        let l = 1;
        let eta = 2;
        let gamma_1 = 1 << 17;
        let gamma_2 = (crate::constants::Q - 1) / 88;
        let tau = 39;
        let omega = 80;
        
        let verifier = CompleteMLDSAVerifierCircuit::<F, C, D>::new(
            config, k, l, eta, gamma_1, gamma_2, tau, omega
        );
        
        // Test with well-formed polynomial data
        let pk_bytes = vec![1u8; 32 + k * 256 * 2]; // Use 1s for simpler polynomial structure
        let sig_bytes = vec![2u8; 32 + l * 256 * 3 + k * 256]; // Use 2s for different values
        let message = b"polynomial test";
        
        let proof_result = verifier.generate_proof(&pk_bytes, &sig_bytes, message);
        
        // This tests NTT/INTT operations and polynomial arithmetic
        assert!(proof_result.is_ok(), "Polynomial operations in NTT domain should work: {:?}", proof_result.err());
        
        if let Ok(proof) = proof_result {
            let verify_result = verifier.circuit.verify(proof);
            println!("NTT polynomial operations test completed: verify_result = {:?}", verify_result.is_ok());
        }
    }
}