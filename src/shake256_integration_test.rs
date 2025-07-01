#[cfg(test)]
mod shake256_integration_tests {
    use crate::complete_verifier::CompleteMLDSAVerifierCircuit;
    use shake256_circuit::Shake256Circuit;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use plonky2::plonk::circuit_data::CircuitConfig;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as plonky2::plonk::config::GenericConfig<D>>::F;

    #[test]
    fn test_shake256_circuit_integration() {
        // Test that we can create and use SHAKE256 circuits alongside ML-DSA verifier
        
        let config = CircuitConfig::standard_recursion_config();
        
        // Create SHAKE256 circuit for ML-DSA hashing patterns
        let shake256_pk_hash = Shake256Circuit::<F, C, D>::new(config.clone(), 1312, 64); // H(pk, 64)
        let shake256_mu = Shake256Circuit::<F, C, D>::new(config.clone(), 128, 64);      // H(tr || m, 64)
        let shake256_challenge = Shake256Circuit::<F, C, D>::new(config.clone(), 832, 32); // H(mu || w', 32)
        
        // Test that we can generate proofs for all ML-DSA hashing patterns
        let pk_data = vec![0x01u8; 1312];
        let tr_msg_data = vec![0x02u8; 128];
        let challenge_data = vec![0x03u8; 832];
        
        // Test public key hashing
        let pk_proof = shake256_pk_hash.generate_proof(&pk_data)
            .expect("Should generate proof for public key hash");
        shake256_pk_hash.circuit.verify(pk_proof)
            .expect("Should verify public key hash proof");
        
        // Test transcript + message hashing
        let mu_proof = shake256_mu.generate_proof(&tr_msg_data)
            .expect("Should generate proof for mu computation");
        shake256_mu.circuit.verify(mu_proof)
            .expect("Should verify mu computation proof");
        
        // Test challenge generation
        let challenge_proof = shake256_challenge.generate_proof(&challenge_data)
            .expect("Should generate proof for challenge generation");
        shake256_challenge.circuit.verify(challenge_proof)
            .expect("Should verify challenge generation proof");
        
        println!("✓ SHAKE256 circuit integration successful for all ML-DSA patterns");
    }

    #[test]
    fn test_mldsa_verifier_with_shake256_available() {
        // Test that ML-DSA verifier can be created when SHAKE256 circuit is available
        
        let config = CircuitConfig::standard_recursion_config();
        
        // Create ML-DSA verifier circuit
        let k = 4;
        let l = 4;
        let eta = 2;
        let gamma_1 = 1 << 17;
        let gamma_2 = (crate::constants::Q - 1) / 88;
        let tau = 39;
        let omega = 80;
        
        let verifier = CompleteMLDSAVerifierCircuit::<F, C, D>::new(
            config.clone(), k, l, eta, gamma_1, gamma_2, tau, omega
        );
        
        // Create SHAKE256 circuits for comparison
        let shake256_circuit = Shake256Circuit::<F, C, D>::new(config, 64, 32);
        
        // Test data
        let pk_bytes = vec![42u8; 32 + k * 256 * 2];
        let sig_bytes = vec![123u8; 32 + l * 256 * 3 + k * 256];
        let message = b"test integration message";
        
        // Test ML-DSA verifier
        let ml_dsa_proof = verifier.generate_proof(&pk_bytes, &sig_bytes, message)
            .expect("ML-DSA verifier should generate proof");
        verifier.circuit.verify(ml_dsa_proof)
            .expect("ML-DSA verifier proof should verify");
        
        // Test SHAKE256 circuit
        let shake_data = b"test shake256 integration";
        let shake_proof = shake256_circuit.generate_proof(shake_data)
            .expect("SHAKE256 circuit should generate proof");
        shake256_circuit.circuit.verify(shake_proof)
            .expect("SHAKE256 proof should verify");
        
        println!("✓ ML-DSA verifier and SHAKE256 circuit work together successfully");
    }

    #[test]
    fn test_reference_shake256_consistency() {
        // Test that our SHAKE256 reference implementation is consistent
        
        let large_input = vec![0x55u8; 1312];
        let test_inputs: Vec<&[u8]> = vec![
            b"",
            b"abc", 
            b"test message for ML-DSA verification",
            &large_input, // ML-DSA public key size
        ];
        
        for input in test_inputs {
            let output1 = Shake256Circuit::<F, C, D>::reference_shake256(input, 64);
            let output2 = Shake256Circuit::<F, C, D>::reference_shake256(input, 64);
            
            assert_eq!(output1, output2, "SHAKE256 reference should be deterministic");
            assert_eq!(output1.len(), 64, "Output should have correct length");
            
            // Different outputs for different lengths
            let output32 = Shake256Circuit::<F, C, D>::reference_shake256(input, 32);
            assert_eq!(output32.len(), 32, "32-byte output should have correct length");
            
            // First 32 bytes should match (SHAKE256 property)
            assert_eq!(&output1[..32], &output32[..], "SHAKE256 should have XOF property");
        }
        
        println!("✓ SHAKE256 reference implementation is consistent");
    }
}