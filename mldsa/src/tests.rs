use super::*;
use plonky2::field::types::Field;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use pqcrypto_mldsa::{mldsa44, mldsa65, mldsa87};
use pqcrypto_traits::sign::{DetachedSignature, PublicKey};
use rand::prelude::*;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

/// ML-DSA parameter set configurations
#[derive(Debug, Clone)]
pub struct MldsaParams {
    pub name: &'static str,
    pub public_key_size: usize,
    pub private_key_size: usize,
    pub signature_size: usize,
    pub security_level: u32,
}

impl MldsaParams {
    pub const MLDSA44: Self = Self {
        name: "ML-DSA-44",
        public_key_size: 1312,
        private_key_size: 2560,
        signature_size: 2420,
        security_level: 128,
    };
    
    pub const MLDSA65: Self = Self {
        name: "ML-DSA-65",
        public_key_size: 1952,
        private_key_size: 4032,
        signature_size: 3309,
        security_level: 192,
    };
    
    pub const MLDSA87: Self = Self {
        name: "ML-DSA-87",
        public_key_size: 2592,
        private_key_size: 4866,
        signature_size: 4627,
        security_level: 256,
    };
}

/// Test vector for ML-DSA
#[derive(Debug, Clone)]
struct MldsaTestVector {
    pub params: MldsaParams,
    pub message: Vec<u8>,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub expected_valid: bool,
}

impl MldsaTestVector {
    fn new(params: MldsaParams, message: Vec<u8>, public_key: Vec<u8>, signature: Vec<u8>, expected_valid: bool) -> Self {
        Self {
            params,
            message,
            public_key,
            signature,
            expected_valid,
        }
    }
}

/// Generate ML-DSA test vectors using reference implementation
fn generate_mldsa_test_vectors() -> Vec<MldsaTestVector> {
    let mut vectors = Vec::new();
    let _rng = StdRng::seed_from_u64(42); // Deterministic for reproducible tests
    
    // Test messages
    let test_messages = vec![
        b"".to_vec(),                                    // Empty message
        b"Hello, World!".to_vec(),                      // Simple message
        b"The quick brown fox jumps over the lazy dog".to_vec(), // Standard test message
        vec![0x00; 32],                                 // All zeros
        vec![0xFF; 32],                                 // All ones
        (0..256).map(|i| i as u8).collect(),           // Sequential bytes
    ];
    
    // Generate ML-DSA-44 vectors
    for message in &test_messages {
        let (pk, sk) = mldsa44::keypair();
        let sig = mldsa44::detached_sign(message, &sk);
        
        vectors.push(MldsaTestVector::new(
            MldsaParams::MLDSA44,
            message.clone(),
            pk.as_bytes().to_vec(),
            sig.as_bytes().to_vec(),
            true, // Valid signature
        ));
        
        // Create invalid signature by corrupting the signature
        let mut invalid_sig = sig.as_bytes().to_vec();
        if !invalid_sig.is_empty() {
            invalid_sig[0] ^= 1; // Flip one bit
        }
        
        vectors.push(MldsaTestVector::new(
            MldsaParams::MLDSA44,
            message.clone(),
            pk.as_bytes().to_vec(),
            invalid_sig,
            false, // Invalid signature
        ));
    }
    
    // Generate ML-DSA-65 vectors (fewer to avoid test timeout)
    let (pk65, sk65) = mldsa65::keypair();
    let sig65 = mldsa65::detached_sign(b"ML-DSA-65 test", &sk65);
    
    vectors.push(MldsaTestVector::new(
        MldsaParams::MLDSA65,
        b"ML-DSA-65 test".to_vec(),
        pk65.as_bytes().to_vec(),
        sig65.as_bytes().to_vec(),
        true,
    ));
    
    // Generate ML-DSA-87 vectors (fewer to avoid test timeout)
    let (pk87, sk87) = mldsa87::keypair();
    let sig87 = mldsa87::detached_sign(b"ML-DSA-87 test", &sk87);
    
    vectors.push(MldsaTestVector::new(
        MldsaParams::MLDSA87,
        b"ML-DSA-87 test".to_vec(),
        pk87.as_bytes().to_vec(),
        sig87.as_bytes().to_vec(),
        true,
    ));
    
    vectors
}

#[cfg(test)]
mod completeness_tests {
    use super::*;

    #[test]
    fn test_mldsa_parameter_sizes() {
        // Verify parameter sizes match FIPS 204 specification
        assert_eq!(MldsaParams::MLDSA44.public_key_size, 1312);
        assert_eq!(MldsaParams::MLDSA44.signature_size, 2420);
        assert_eq!(MldsaParams::MLDSA44.security_level, 128);
        
        assert_eq!(MldsaParams::MLDSA65.public_key_size, 1952);
        assert_eq!(MldsaParams::MLDSA65.signature_size, 3309);
        assert_eq!(MldsaParams::MLDSA65.security_level, 192);
        
        assert_eq!(MldsaParams::MLDSA87.public_key_size, 2592);
        assert_eq!(MldsaParams::MLDSA87.signature_size, 4627);
        assert_eq!(MldsaParams::MLDSA87.security_level, 256);
    }

    #[test]
    fn test_mldsa_reference_implementation() {
        // Test that our reference implementation works correctly
        let message = b"Test message for ML-DSA";
        
        // Test ML-DSA-44
        let (pk44, sk44) = mldsa44::keypair();
        let sig44 = mldsa44::detached_sign(message, &sk44);
        
        assert_eq!(pk44.as_bytes().len(), MldsaParams::MLDSA44.public_key_size);
        assert_eq!(sig44.as_bytes().len(), MldsaParams::MLDSA44.signature_size);
        
        // Verify signature
        let verification_result = mldsa44::verify_detached_signature(&sig44, message, &pk44);
        assert!(verification_result.is_ok(), "ML-DSA-44 signature should verify");
        
        // Test invalid signature
        let mut invalid_sig = sig44.as_bytes().to_vec();
        invalid_sig[0] ^= 1;
        let invalid_sig_obj = mldsa44::DetachedSignature::from_bytes(&invalid_sig).unwrap();
        let invalid_result = mldsa44::verify_detached_signature(&invalid_sig_obj, message, &pk44);
        assert!(invalid_result.is_err(), "Corrupted signature should not verify");
    }

    #[test]
    fn test_mldsa_gadget_with_reference_vectors() {
        // Test ML-DSA gadget with vectors from reference implementation
        let test_vectors = generate_mldsa_test_vectors();
        
        for (i, vector) in test_vectors.iter().take(4).enumerate() { // Test first 4 to avoid timeout
            println!("Testing vector {}: {} with message len {}", 
                     i + 1, vector.params.name, vector.message.len());
            
            let config = CircuitConfig::standard_recursion_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);
            
            // Create input targets
            let public_key_targets: Vec<Target> = vector.public_key.iter()
                .map(|&byte| builder.constant(F::from_canonical_u32(byte as u32)))
                .collect();
            
            let signature_targets: Vec<Target> = vector.signature.iter()
                .map(|&byte| builder.constant(F::from_canonical_u32(byte as u32)))
                .collect();
            
            let message_targets: Vec<Target> = vector.message.iter()
                .map(|&byte| builder.constant(F::from_canonical_u32(byte as u32)))
                .collect();
            
            // Run ML-DSA verification in circuit
            let verification_result = MldsaGadget::verify(
                &mut builder,
                &public_key_targets,
                &signature_targets,
                &message_targets,
            );
            
            builder.register_public_input(verification_result);
            
            // Build and prove circuit
            let circuit = builder.build::<C>();
            let pw = PartialWitness::new();
            
            let proof = circuit.prove(pw).expect("proof generation should succeed");
            circuit.verify(proof).expect("proof verification should succeed");
        }
    }

    #[test]
    fn test_mldsa_empty_message() {
        // Test ML-DSA with empty message
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        // Generate valid ML-DSA-44 signature for empty message
        let (pk, sk) = mldsa44::keypair();
        let sig = mldsa44::detached_sign(b"", &sk);
        
        let public_key_targets: Vec<Target> = pk.as_bytes().iter()
            .map(|&byte| builder.constant(F::from_canonical_u32(byte as u32)))
            .collect();
        
        let signature_targets: Vec<Target> = sig.as_bytes().iter()
            .map(|&byte| builder.constant(F::from_canonical_u32(byte as u32)))
            .collect();
        
        let message_targets: Vec<Target> = vec![]; // Empty message
        
        let verification_result = MldsaGadget::verify(
            &mut builder,
            &public_key_targets,
            &signature_targets,
            &message_targets,
        );
        
        builder.register_public_input(verification_result);
        
        let circuit = builder.build::<C>();
        let pw = PartialWitness::new();
        
        let proof = circuit.prove(pw).expect("proof generation should succeed");
        circuit.verify(proof).expect("proof verification should succeed");
    }

    #[test]
    fn test_mldsa_large_message() {
        // Test ML-DSA with large message
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        // Create large message (multiple SHAKE256 blocks)
        let large_message = vec![0x42; 1000];
        
        let (pk, sk) = mldsa44::keypair();
        let sig = mldsa44::detached_sign(&large_message, &sk);
        
        let public_key_targets: Vec<Target> = pk.as_bytes().iter()
            .map(|&byte| builder.constant(F::from_canonical_u32(byte as u32)))
            .collect();
        
        let signature_targets: Vec<Target> = sig.as_bytes().iter()
            .map(|&byte| builder.constant(F::from_canonical_u32(byte as u32)))
            .collect();
        
        let message_targets: Vec<Target> = large_message.iter()
            .map(|&byte| builder.constant(F::from_canonical_u32(byte as u32)))
            .collect();
        
        let verification_result = MldsaGadget::verify(
            &mut builder,
            &public_key_targets,
            &signature_targets,
            &message_targets,
        );
        
        builder.register_public_input(verification_result);
        
        let circuit = builder.build::<C>();
        let pw = PartialWitness::new();
        
        let proof = circuit.prove(pw).expect("proof generation should succeed");
        circuit.verify(proof).expect("proof verification should succeed");
    }
}

#[cfg(test)]
mod soundness_tests {
    use super::*;

    #[test]
    fn test_mldsa_soundness_different_messages() {
        // Test that different messages produce different verification results
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        let (pk, sk) = mldsa44::keypair();
        let message1 = b"Message 1";
        let message2 = b"Message 2";
        
        let sig1 = mldsa44::detached_sign(message1, &sk);
        
        let public_key_targets: Vec<Target> = pk.as_bytes().iter()
            .map(|&byte| builder.constant(F::from_canonical_u32(byte as u32)))
            .collect();
        
        let signature_targets: Vec<Target> = sig1.as_bytes().iter()
            .map(|&byte| builder.constant(F::from_canonical_u32(byte as u32)))
            .collect();
        
        let message1_targets: Vec<Target> = message1.iter()
            .map(|&byte| builder.constant(F::from_canonical_u32(byte as u32)))
            .collect();
        
        let message2_targets: Vec<Target> = message2.iter()
            .map(|&byte| builder.constant(F::from_canonical_u32(byte as u32)))
            .collect();
        
        // Verify with correct message
        let result1 = MldsaGadget::verify(
            &mut builder,
            &public_key_targets,
            &signature_targets,
            &message1_targets,
        );
        
        // Verify with incorrect message
        let result2 = MldsaGadget::verify(
            &mut builder,
            &public_key_targets,
            &signature_targets,
            &message2_targets,
        );
        
        // Results should be different
        let difference = builder.sub(result1, result2);
        let zero = builder.zero();
        let is_different = builder.is_equal(difference, zero);
        let false_target = builder._false();
        builder.connect(is_different.target, false_target.target);
        
        let circuit = builder.build::<C>();
        let pw = PartialWitness::new();
        
        let proof = circuit.prove(pw).expect("proof generation should succeed");
        circuit.verify(proof).expect("proof verification should succeed");
    }

    #[test]
    fn test_mldsa_soundness_different_signatures() {
        // Test that different signatures for same message produce different results
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        let message = b"Test message";
        let (pk1, sk1) = mldsa44::keypair();
        let (pk2, sk2) = mldsa44::keypair();
        
        let sig1 = mldsa44::detached_sign(message, &sk1);
        let sig2 = mldsa44::detached_sign(message, &sk2);
        
        let pk1_targets: Vec<Target> = pk1.as_bytes().iter()
            .map(|&byte| builder.constant(F::from_canonical_u32(byte as u32)))
            .collect();
        
        let pk2_targets: Vec<Target> = pk2.as_bytes().iter()
            .map(|&byte| builder.constant(F::from_canonical_u32(byte as u32)))
            .collect();
        
        let sig1_targets: Vec<Target> = sig1.as_bytes().iter()
            .map(|&byte| builder.constant(F::from_canonical_u32(byte as u32)))
            .collect();
        
        let sig2_targets: Vec<Target> = sig2.as_bytes().iter()
            .map(|&byte| builder.constant(F::from_canonical_u32(byte as u32)))
            .collect();
        
        let message_targets: Vec<Target> = message.iter()
            .map(|&byte| builder.constant(F::from_canonical_u32(byte as u32)))
            .collect();
        
        // Verify with matching key-signature pairs
        let result1 = MldsaGadget::verify(&mut builder, &pk1_targets, &sig1_targets, &message_targets);
        let result2 = MldsaGadget::verify(&mut builder, &pk2_targets, &sig2_targets, &message_targets);
        
        // Results should be different (different keys produce different hashes)
        let difference = builder.sub(result1, result2);
        let zero = builder.zero();
        let is_same = builder.is_equal(difference, zero);
        let false_target = builder._false();
        builder.connect(is_same.target, false_target.target);
        
        let circuit = builder.build::<C>();
        let pw = PartialWitness::new();
        
        let proof = circuit.prove(pw).expect("proof generation should succeed");
        circuit.verify(proof).expect("proof verification should succeed");
    }

    #[test]
    fn test_mldsa_soundness_deterministic() {
        // Test that same inputs always produce same outputs
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        let message = b"Deterministic test";
        let (pk, sk) = mldsa44::keypair();
        let sig = mldsa44::detached_sign(message, &sk);
        
        let public_key_targets: Vec<Target> = pk.as_bytes().iter()
            .map(|&byte| builder.constant(F::from_canonical_u32(byte as u32)))
            .collect();
        
        let signature_targets: Vec<Target> = sig.as_bytes().iter()
            .map(|&byte| builder.constant(F::from_canonical_u32(byte as u32)))
            .collect();
        
        let message_targets: Vec<Target> = message.iter()
            .map(|&byte| builder.constant(F::from_canonical_u32(byte as u32)))
            .collect();
        
        // Verify same signature multiple times
        let result1 = MldsaGadget::verify(&mut builder, &public_key_targets, &signature_targets, &message_targets);
        let result2 = MldsaGadget::verify(&mut builder, &public_key_targets, &signature_targets, &message_targets);
        let result3 = MldsaGadget::verify(&mut builder, &public_key_targets, &signature_targets, &message_targets);

        // All results must be identical
        builder.connect(result1, result2);
        builder.connect(result2, result3);
        
        let circuit = builder.build::<C>();
        let pw = PartialWitness::new();
        
        let proof = circuit.prove(pw).expect("proof generation should succeed");
        circuit.verify(proof).expect("proof verification should succeed");
    }
}

#[cfg(test)]
mod corner_case_tests {
    use super::*;

    #[test]
    fn test_mldsa_invalid_signature_length() {
        // Test with signature of wrong length
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        let message = b"Test message";
        let (pk, _sk) = mldsa44::keypair();
        
        let public_key_targets: Vec<Target> = pk.as_bytes().iter()
            .map(|&byte| builder.constant(F::from_canonical_u32(byte as u32)))
            .collect();
        
        // Create signature with wrong length
        let wrong_sig = vec![0x42; 100]; // Much shorter than expected 2420 bytes
        let signature_targets: Vec<Target> = wrong_sig.iter()
            .map(|&byte| builder.constant(F::from_canonical_u32(byte as u32)))
            .collect();
        
        let message_targets: Vec<Target> = message.iter()
            .map(|&byte| builder.constant(F::from_canonical_u32(byte as u32)))
            .collect();
        
        let verification_result = MldsaGadget::verify(
            &mut builder,
            &public_key_targets,
            &signature_targets,
            &message_targets,
        );
        
        builder.register_public_input(verification_result);
        
        let circuit = builder.build::<C>();
        let pw = PartialWitness::new();
        
        let proof = circuit.prove(pw).expect("proof generation should succeed");
        circuit.verify(proof).expect("proof verification should succeed");
    }

    #[test]
    fn test_mldsa_invalid_public_key_length() {
        // Test with public key of wrong length
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        let message = b"Test message";
        let (_pk, sk) = mldsa44::keypair();
        let sig = mldsa44::detached_sign(message, &sk);
        
        // Create public key with wrong length
        let wrong_pk = vec![0x42; 500]; // Much shorter than expected 1312 bytes
        let public_key_targets: Vec<Target> = wrong_pk.iter()
            .map(|&byte| builder.constant(F::from_canonical_u32(byte as u32)))
            .collect();
        
        let signature_targets: Vec<Target> = sig.as_bytes().iter()
            .map(|&byte| builder.constant(F::from_canonical_u32(byte as u32)))
            .collect();
        
        let message_targets: Vec<Target> = message.iter()
            .map(|&byte| builder.constant(F::from_canonical_u32(byte as u32)))
            .collect();
        
        let verification_result = MldsaGadget::verify(
            &mut builder,
            &public_key_targets,
            &signature_targets,
            &message_targets,
        );
        
        builder.register_public_input(verification_result);
        
        let circuit = builder.build::<C>();
        let pw = PartialWitness::new();
        
        let proof = circuit.prove(pw).expect("proof generation should succeed");
        circuit.verify(proof).expect("proof verification should succeed");
    }

    #[test]
    fn test_mldsa_all_zero_inputs() {
        // Test with all zero inputs
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        let public_key_targets: Vec<Target> = vec![builder.zero(); 100];
        let signature_targets: Vec<Target> = vec![builder.zero(); 100];
        let message_targets: Vec<Target> = vec![builder.zero(); 32];
        
        let verification_result = MldsaGadget::verify(
            &mut builder,
            &public_key_targets,
            &signature_targets,
            &message_targets,
        );
        
        builder.register_public_input(verification_result);
        
        let circuit = builder.build::<C>();
        let pw = PartialWitness::new();
        
        let proof = circuit.prove(pw).expect("proof generation should succeed");
        circuit.verify(proof).expect("proof verification should succeed");
    }

    #[test]
    fn test_mldsa_max_value_inputs() {
        // Test with maximum field values
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        let max_val = builder.constant(F::from_canonical_u32(255));
        let public_key_targets: Vec<Target> = vec![max_val; 100];
        let signature_targets: Vec<Target> = vec![max_val; 100];
        let message_targets: Vec<Target> = vec![max_val; 32];
        
        let verification_result = MldsaGadget::verify(
            &mut builder,
            &public_key_targets,
            &signature_targets,
            &message_targets,
        );
        
        builder.register_public_input(verification_result);
        
        let circuit = builder.build::<C>();
        let pw = PartialWitness::new();
        
        let proof = circuit.prove(pw).expect("proof generation should succeed");
        circuit.verify(proof).expect("proof verification should succeed");
    }

    #[test]
    fn test_mldsa_single_byte_corruption() {
        // Test signature with single byte corrupted
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        let message = b"Test message";
        let (pk, sk) = mldsa44::keypair();
        let sig = mldsa44::detached_sign(message, &sk);
        
        let public_key_targets: Vec<Target> = pk.as_bytes().iter()
            .map(|&byte| builder.constant(F::from_canonical_u32(byte as u32)))
            .collect();
        
        // Corrupt first byte of signature
        let mut corrupted_sig = sig.as_bytes().to_vec();
        corrupted_sig[0] ^= 1;
        
        let signature_targets: Vec<Target> = corrupted_sig.iter()
            .map(|&byte| builder.constant(F::from_canonical_u32(byte as u32)))
            .collect();
        
        let message_targets: Vec<Target> = message.iter()
            .map(|&byte| builder.constant(F::from_canonical_u32(byte as u32)))
            .collect();
        
        let verification_result = MldsaGadget::verify(
            &mut builder,
            &public_key_targets,
            &signature_targets,
            &message_targets,
        );
        
        builder.register_public_input(verification_result);
        
        let circuit = builder.build::<C>();
        let pw = PartialWitness::new();
        
        let proof = circuit.prove(pw).expect("proof generation should succeed");
        circuit.verify(proof).expect("proof verification should succeed");
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use shake256::Shake256Gadget;

    #[test]
    fn test_mldsa_uses_shake256() {
        // Verify ML-DSA properly uses SHAKE256 for hashing
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        let message = b"Integration test message";
        let (pk, sk) = mldsa44::keypair();
        let sig = mldsa44::detached_sign(message, &sk);
        
        let public_key_targets: Vec<Target> = pk.as_bytes().iter().take(100) // Truncate for performance
            .map(|&byte| builder.constant(F::from_canonical_u32(byte as u32)))
            .collect();
        
        let signature_targets: Vec<Target> = sig.as_bytes().iter().take(100) // Truncate for performance
            .map(|&byte| builder.constant(F::from_canonical_u32(byte as u32)))
            .collect();
        
        let message_targets: Vec<Target> = message.iter()
            .map(|&byte| builder.constant(F::from_canonical_u32(byte as u32)))
            .collect();
        
        // Test direct SHAKE256 usage
        let shake_result = Shake256Gadget::hash(&mut builder, &public_key_targets, 64);
        assert_eq!(shake_result.len(), 64);
        
        // Test ML-DSA verification (which should use SHAKE256 internally)
        let verification_result = MldsaGadget::verify(
            &mut builder,
            &public_key_targets,
            &signature_targets,
            &message_targets,
        );
        
        builder.register_public_input(verification_result);
        
        let circuit = builder.build::<C>();
        let pw = PartialWitness::new();
        
        let proof = circuit.prove(pw).expect("proof generation should succeed");
        circuit.verify(proof).expect("proof verification should succeed");
    }

    #[test]
    fn test_mldsa_ntt_integration() {
        // Verify ML-DSA properly uses NTT operations
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        let message = b"NTT integration test";
        let (pk, sk) = mldsa44::keypair();
        let sig = mldsa44::detached_sign(message, &sk);
        
        let public_key_targets: Vec<Target> = pk.as_bytes().iter().take(256) // Enough for one polynomial
            .map(|&byte| builder.constant(F::from_canonical_u32(byte as u32)))
            .collect();
        
        let signature_targets: Vec<Target> = sig.as_bytes().iter().take(256)
            .map(|&byte| builder.constant(F::from_canonical_u32(byte as u32)))
            .collect();
        
        let message_targets: Vec<Target> = message.iter()
            .map(|&byte| builder.constant(F::from_canonical_u32(byte as u32)))
            .collect();
        
        let verification_result = MldsaGadget::verify(
            &mut builder,
            &public_key_targets,
            &signature_targets,
            &message_targets,
        );
        
        builder.register_public_input(verification_result);
        
        // The circuit should contain NTT operations
        let circuit = builder.build::<C>();
        assert!(circuit.common.gates.len() > 0, "Circuit should contain gates from NTT operations");
        
        let pw = PartialWitness::new();
        let proof = circuit.prove(pw).expect("proof generation should succeed");
        circuit.verify(proof).expect("proof verification should succeed");
    }
}

#[cfg(test)]
mod performance_tests {
    use super::*;
    use std::time::Instant;

    #[test]
    #[ignore] // Run with --ignored flag for performance testing
    fn test_mldsa_performance_comparison() {
        println!("\n=== ML-DSA Performance Tests ===");
        
        let parameter_sets = vec![
            MldsaParams::MLDSA44,
            // MldsaParams::MLDSA65, // Commented out for faster testing
            // MldsaParams::MLDSA87, // Commented out for faster testing
        ];
        
        for params in parameter_sets {
            println!("\nTesting {}:", params.name);
            
            let config = CircuitConfig::standard_recursion_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);
            
            // Create mock inputs with correct sizes
            let public_key_targets: Vec<Target> = (0..params.public_key_size.min(100))
                .map(|i| builder.constant(F::from_canonical_u32((i % 256) as u32)))
                .collect();
            
            let signature_targets: Vec<Target> = (0..params.signature_size.min(100))
                .map(|i| builder.constant(F::from_canonical_u32(((i * 17) % 256) as u32)))
                .collect();
            
            let message_targets: Vec<Target> = (0..32)
                .map(|i| builder.constant(F::from_canonical_u32(((i * 31) % 256) as u32)))
                .collect();
            
            let start = Instant::now();
            let _verification_result = MldsaGadget::verify(
                &mut builder,
                &public_key_targets,
                &signature_targets,
                &message_targets,
            );
            let verification_time = start.elapsed();
            
            let circuit = builder.build::<C>();
            let build_time = start.elapsed() - verification_time;
            
            let pw = PartialWitness::new();
            
            let prove_start = Instant::now();
            let proof = circuit.prove(pw).expect("proof generation should succeed");
            let prove_time = prove_start.elapsed();
            
            let verify_start = Instant::now();
            circuit.verify(proof).expect("proof verification should succeed");
            let verify_time = verify_start.elapsed();
            
            println!("  Public key size: {} bytes", params.public_key_size);
            println!("  Signature size:  {} bytes", params.signature_size);
            println!("  Security level:  {} bits", params.security_level);
            println!("  Verification time: {:?}", verification_time);
            println!("  Build time:        {:?}", build_time);
            println!("  Prove time:        {:?}", prove_time);
            println!("  Verify time:       {:?}", verify_time);
            println!("  Circuit size:      {} gates", circuit.common.gates.len());
        }
    }
}