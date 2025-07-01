#[cfg(test)]
mod verification_tests {
    use crate::mldsa_verifier::{MLDSAVerifier, mldsa44_params, mldsa65_params, mldsa87_params};
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use pqcrypto_mldsa::{mldsa44, mldsa65, mldsa87};
    use pqcrypto_traits::sign::{PublicKey, SignedMessage};
    
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    /// Test ML-DSA-44 signature verification with good signature
    #[test]
    fn test_mldsa44_good_signature() {
        // Generate real ML-DSA-44 key pair
        let (pk, sk) = mldsa44::keypair();
        let message = b"Test message for ML-DSA-44 verification";
        
        // Sign the message
        let signed_message = mldsa44::sign(message, &sk);
        
        // Verify signature using pqcrypto (should pass)
        let verified_message = mldsa44::open(&signed_message, &pk)
            .expect("pqcrypto verification should pass");
        assert_eq!(message.as_slice(), verified_message.as_slice());
        
        // Create ZK verifier circuit
        let config = CircuitConfig::standard_recursion_config();
        let (k, l, d, eta, tau, gamma_1, gamma_2, omega, c_tilde_bytes) = mldsa44_params();
        let verifier = MLDSAVerifier::<F, C, D>::new(
            config, k, l, d, eta, tau, gamma_1, gamma_2, omega, c_tilde_bytes
        );
        
        // Extract components
        let pk_bytes = pk.as_bytes();
        let sig_bytes = extract_signature_bytes(&signed_message, message);
        
        // Generate ZK proof
        let proof_result = verifier.generate_proof(pk_bytes, &sig_bytes, message);
        if let Err(e) = &proof_result {
            println!("Proof generation error: {:?}", e);
        }
        assert!(proof_result.is_ok(), "Proof generation should succeed for valid signature");
        
        // Verify ZK proof
        let proof = proof_result.unwrap();
        let verify_result = verifier.circuit.verify(proof.clone());
        assert!(verify_result.is_ok(), "ZK proof verification should succeed for valid signature");
        
        // Check that the proof indicates the signature is valid
        let is_valid = verifier.is_signature_valid(&proof);
        assert!(is_valid, "Good signature should be detected as valid by the circuit");
    }

    /// Test ML-DSA-44 signature verification with bad signature (corrupted)
    #[test] 
    fn test_mldsa44_bad_signature() {
        // Generate real ML-DSA-44 key pair
        let (pk, sk) = mldsa44::keypair();
        let message = b"Test message for ML-DSA-44 verification";
        
        // Sign the message
        let signed_message = mldsa44::sign(message, &sk);
        
        // Corrupt the signature
        let mut bytes = signed_message.as_bytes().to_vec();
        bytes[100] ^= 0x01; // Flip one bit
        let signed_message = SignedMessage::from_bytes(&bytes).unwrap();
        
        // Verify signature using pqcrypto (should fail)
        let verify_result = mldsa44::open(&signed_message, &pk);
        assert!(verify_result.is_err(), "pqcrypto verification should fail for corrupted signature");
        
        // Create ZK verifier circuit
        let config = CircuitConfig::standard_recursion_config();
        let (k, l, d, eta, tau, gamma_1, gamma_2, omega, c_tilde_bytes) = mldsa44_params();
        let verifier = MLDSAVerifier::<F, C, D>::new(
            config, k, l, d, eta, tau, gamma_1, gamma_2, omega, c_tilde_bytes
        );
        
        // Extract components (using original message for fair test)
        let pk_bytes = pk.as_bytes();
        let sig_bytes = extract_signature_bytes(&signed_message, message);
        
        // Generate ZK proof (should still succeed as it's about circuit construction)
        let proof_result = verifier.generate_proof(pk_bytes, &sig_bytes, message);
        assert!(proof_result.is_ok(), "Proof generation should succeed even for bad signatures");
        
        let proof = proof_result.unwrap();
        
        // Verify the ZK proof itself is valid
        let verify_result = verifier.circuit.verify(proof.clone());
        assert!(verify_result.is_ok(), "ZK proof should be valid even for bad signatures");
        
        // Check that the proof indicates the signature is invalid
        let is_valid = verifier.is_signature_valid(&proof);
        assert!(!is_valid, "Bad signature should be detected as invalid by the circuit");
    }

    /// Test ML-DSA-65 signature verification
    #[test]
    fn test_mldsa65_good_signature() {
        let (pk, sk) = mldsa65::keypair();
        let message = b"Test message for ML-DSA-65 verification";
        
        let signed_message = mldsa65::sign(message, &sk);
        let verified_message = mldsa65::open(&signed_message, &pk)
            .expect("pqcrypto verification should pass");
        assert_eq!(message.as_slice(), verified_message.as_slice());
        
        let config = CircuitConfig::standard_recursion_config();
        let (k, l, d, eta, tau, gamma_1, gamma_2, omega, c_tilde_bytes) = mldsa65_params();
        let verifier = MLDSAVerifier::<F, C, D>::new(
            config, k, l, d, eta, tau, gamma_1, gamma_2, omega, c_tilde_bytes
        );
        
        let pk_bytes = pk.as_bytes();
        let sig_bytes = extract_signature_bytes(&signed_message, message);
        
        let proof_result = verifier.generate_proof(pk_bytes, &sig_bytes, message);
        assert!(proof_result.is_ok(), "Proof generation should succeed for ML-DSA-65");
        
        let proof = proof_result.unwrap();
        let verify_result = verifier.circuit.verify(proof.clone());
        assert!(verify_result.is_ok(), "ZK proof verification should succeed for ML-DSA-65");
        
        // Check that the proof indicates the signature is valid
        let is_valid = verifier.is_signature_valid(&proof);
        assert!(is_valid, "Good ML-DSA-65 signature should be detected as valid");
    }

    /// Test ML-DSA-87 signature verification  
    #[test]
    fn test_mldsa87_good_signature() {
        let (pk, sk) = mldsa87::keypair();
        let message = b"Test message for ML-DSA-87 verification";
        
        let signed_message = mldsa87::sign(message, &sk);
        let verified_message = mldsa87::open(&signed_message, &pk)
            .expect("pqcrypto verification should pass");
        assert_eq!(message.as_slice(), verified_message.as_slice());
        
        let config = CircuitConfig::standard_recursion_config();
        let (k, l, d, eta, tau, gamma_1, gamma_2, omega, c_tilde_bytes) = mldsa87_params();
        let verifier = MLDSAVerifier::<F, C, D>::new(
            config, k, l, d, eta, tau, gamma_1, gamma_2, omega, c_tilde_bytes
        );
        
        let pk_bytes = pk.as_bytes();
        let sig_bytes = extract_signature_bytes(&signed_message, message);
        
        let proof_result = verifier.generate_proof(pk_bytes, &sig_bytes, message);
        if let Err(e) = &proof_result {
            println!("ML-DSA-87 proof generation error: {:?}", e);
        }
        assert!(proof_result.is_ok(), "Proof generation should succeed for ML-DSA-87");
        
        let proof = proof_result.unwrap();
        let verify_result = verifier.circuit.verify(proof.clone());
        assert!(verify_result.is_ok(), "ZK proof verification should succeed for ML-DSA-87");
        
        // Check that the proof indicates the signature is valid
        let is_valid = verifier.is_signature_valid(&proof);
        assert!(is_valid, "Good ML-DSA-87 signature should be detected as valid");
    }

    /// Test signature verification with wrong public key
    #[test]
    fn test_mldsa44_wrong_public_key() {
        // Generate two key pairs
        let (_pk1, sk1) = mldsa44::keypair();
        let (pk2, _sk2) = mldsa44::keypair();
        let message = b"Test message for wrong key test";
        
        // Sign with first key
        let signed_message = mldsa44::sign(message, &sk1);
        
        // Try to verify with second key (should fail)
        let verify_result = mldsa44::open(&signed_message, &pk2);
        assert!(verify_result.is_err(), "Verification should fail with wrong public key");
        
        // Test with ZK circuit
        let config = CircuitConfig::standard_recursion_config();
        let (k, l, d, eta, tau, gamma_1, gamma_2, omega, c_tilde_bytes) = mldsa44_params();
        let verifier = MLDSAVerifier::<F, C, D>::new(
            config, k, l, d, eta, tau, gamma_1, gamma_2, omega, c_tilde_bytes
        );
        
        // Use wrong public key
        let pk_bytes = pk2.as_bytes();
        let sig_bytes = extract_signature_bytes(&signed_message, message);
        
        let proof_result = verifier.generate_proof(pk_bytes, &sig_bytes, message);
        assert!(proof_result.is_ok(), "Proof generation should succeed even with wrong key");
        
        let proof = proof_result.unwrap();
        
        // Verify the ZK proof itself is valid
        let verify_result = verifier.circuit.verify(proof.clone());
        assert!(verify_result.is_ok(), "ZK proof should be valid even with wrong key");
        
        // Check that the proof indicates the signature is invalid
        let is_valid = verifier.is_signature_valid(&proof);
        assert!(!is_valid, "Wrong public key should cause signature to be detected as invalid");
    }

    /// Extract signature bytes from signed message, removing the original message
    fn extract_signature_bytes<T: SignedMessage>(signed_message: &T, original_message: &[u8]) -> Vec<u8> {
        let signed_bytes = signed_message.as_bytes();
        let msg_len = original_message.len();
        
        // The signed message format is: signature || message
        if signed_bytes.len() >= msg_len {
            signed_bytes[..signed_bytes.len() - msg_len].to_vec()
        } else {
            // Fallback: return full signed bytes if format is unexpected
            signed_bytes.to_vec()
        }
    }

    /// Test signature verification with corrupted c_tilde (challenge)
    /// This specifically tests that c' computation is working correctly
    #[test]
    fn test_mldsa44_corrupted_challenge() {
        // Generate real ML-DSA-44 key pair
        let (pk, sk) = mldsa44::keypair();
        let message = b"Test message for c_tilde corruption test";
        
        // Sign the message
        let signed_message = mldsa44::sign(message, &sk);
        
        // Corrupt only the c_tilde part (first 32 bytes of signature for ML-DSA-44)
        let mut bytes = signed_message.as_bytes().to_vec();
        bytes[0] ^= 0x01; // Flip one bit in c_tilde
        let corrupted_signed_message = SignedMessage::from_bytes(&bytes).unwrap();
        
        // Verify signature using pqcrypto (should fail)
        let verify_result = mldsa44::open(&corrupted_signed_message, &pk);
        assert!(verify_result.is_err(), "pqcrypto verification should fail for corrupted c_tilde");
        
        // Create ZK verifier circuit
        let config = CircuitConfig::standard_recursion_config();
        let (k, l, d, eta, tau, gamma_1, gamma_2, omega, c_tilde_bytes) = mldsa44_params();
        let verifier = MLDSAVerifier::<F, C, D>::new(
            config, k, l, d, eta, tau, gamma_1, gamma_2, omega, c_tilde_bytes
        );
        
        // Extract components
        let pk_bytes = pk.as_bytes();
        let sig_bytes = extract_signature_bytes(&corrupted_signed_message, message);
        
        // Generate ZK proof
        let proof_result = verifier.generate_proof(pk_bytes, &sig_bytes, message);
        assert!(proof_result.is_ok(), "Proof generation should succeed");
        
        let proof = proof_result.unwrap();
        
        // Check that the proof indicates the signature is invalid
        let is_valid = verifier.is_signature_valid(&proof);
        assert!(!is_valid, "Corrupted c_tilde should be detected as invalid by the circuit");
    }

    /// Test that verifies c' is computed correctly by checking multiple bit flips
    #[test]
    fn test_mldsa44_multiple_c_tilde_corruptions() {
        let (pk, sk) = mldsa44::keypair();
        let message = b"Test c' computation verification";
        
        // Sign the message
        let signed_message = mldsa44::sign(message, &sk);
        let original_bytes = signed_message.as_bytes().to_vec();
        
        // Test corrupting different positions in c_tilde
        for bit_pos in [0, 8, 16, 24, 31] {
            let mut bytes = original_bytes.clone();
            bytes[bit_pos] ^= 0xFF; // Flip all bits in that byte
            
            let corrupted_signed_message = mldsa44::SignedMessage::from_bytes(&bytes).unwrap();
            
            // Create ZK verifier circuit
            let config = CircuitConfig::standard_recursion_config();
            let (k, l, d, eta, tau, gamma_1, gamma_2, omega, c_tilde_bytes) = mldsa44_params();
            let verifier = MLDSAVerifier::<F, C, D>::new(
                config, k, l, d, eta, tau, gamma_1, gamma_2, omega, c_tilde_bytes
            );
            
            let pk_bytes = pk.as_bytes();
            let sig_bytes = extract_signature_bytes(&corrupted_signed_message, message);
            
            let proof_result = verifier.generate_proof(pk_bytes, &sig_bytes, message);
            assert!(proof_result.is_ok(), "Proof generation should succeed for bit position {}", bit_pos);
            
            let proof = proof_result.unwrap();
            let is_valid = verifier.is_signature_valid(&proof);
            assert!(!is_valid, "Corruption at c_tilde byte {} should be detected", bit_pos);
        }
    }

    /// Integration test with different message sizes
    #[test]
    fn test_different_message_sizes() {
        let (pk, sk) = mldsa44::keypair();
        
        let test_messages = vec![
            b"short".to_vec(),
            b"This is a medium length message for testing".to_vec(),
            vec![0u8; 100], // 100 zero bytes
            vec![0xAB; 256], // 256 bytes of 0xAB
        ];
        
        let config = CircuitConfig::standard_recursion_config();
        let (k, l, d, eta, tau, gamma_1, gamma_2, omega, c_tilde_bytes) = mldsa44_params();
        let verifier = MLDSAVerifier::<F, C, D>::new(
            config, k, l, d, eta, tau, gamma_1, gamma_2, omega, c_tilde_bytes
        );
        
        for (i, message) in test_messages.iter().enumerate() {
            println!("Testing message {} of length {}", i, message.len());
            
            let signed_message = mldsa44::sign(message, &sk);
            let verified_message = mldsa44::open(&signed_message, &pk)
                .expect("pqcrypto verification should pass");
            assert_eq!(message.as_slice(), verified_message.as_slice());
            
            let pk_bytes = pk.as_bytes();
            let sig_bytes = extract_signature_bytes(&signed_message, message);
            
            let proof_result = verifier.generate_proof(pk_bytes, &sig_bytes, message);
            assert!(proof_result.is_ok(), "Proof generation should succeed for message {}", i);
        }
    }
}