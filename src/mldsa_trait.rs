use anyhow::Result;
use pqcrypto_traits::sign::{PublicKey, SecretKey, SignedMessage};
use crate::mldsa_verifier::{MLDSAVerifier, mldsa44_params, mldsa65_params, mldsa87_params};
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::plonk::circuit_data::CircuitConfig;

/// Trait for ML-DSA signature operations across all variants
pub trait MLDSAVariant {
    type PublicKey: PublicKey;
    type SecretKey: SecretKey;
    
    /// Security level (2, 3, or 5)
    fn security_level(&self) -> u8;
    
    /// Parameter K (dimension of matrix A)
    fn k(&self) -> usize;
    
    /// Parameter L (dimension of secret vector)
    fn l(&self) -> usize;
    
    /// Generate a keypair
    fn generate_keypair(&self) -> (Self::PublicKey, Self::SecretKey);
    
    /// Sign a message
    fn sign_message(&self, secret_key: &Self::SecretKey, message: &[u8]) -> Result<Vec<u8>>;
    
    /// Verify a signature by constructing a ZK circuit that proves the signature is valid
    fn verify_signature(&self, public_key: &Self::PublicKey, signed_message: &[u8]) -> Result<Vec<u8>>;
    
    /// Extract raw signature data for ZK circuit
    fn get_signature_data(
        &self,
        public_key: &Self::PublicKey,
        signed_message: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)>;
}

/// ML-DSA-44 (Security Level 2)
pub struct MLDSA44;

/// ML-DSA-65 (Security Level 3) 
pub struct MLDSA65;

/// ML-DSA-87 (Security Level 5)
pub struct MLDSA87;

impl MLDSAVariant for MLDSA44 {
    type PublicKey = pqcrypto_mldsa::mldsa44::PublicKey;
    type SecretKey = pqcrypto_mldsa::mldsa44::SecretKey;
    
    fn security_level(&self) -> u8 { 2 }
    fn k(&self) -> usize { 4 }
    fn l(&self) -> usize { 4 }
    
    fn generate_keypair(&self) -> (Self::PublicKey, Self::SecretKey) {
        pqcrypto_mldsa::mldsa44::keypair()
    }
    
    fn sign_message(&self, secret_key: &Self::SecretKey, message: &[u8]) -> Result<Vec<u8>> {
        let signed_msg = pqcrypto_mldsa::mldsa44::sign(message, secret_key);
        Ok(signed_msg.as_bytes().to_vec())
    }
    
    fn verify_signature(&self, public_key: &Self::PublicKey, signed_message: &[u8]) -> Result<Vec<u8>> {
        // First do conventional verification to get the message
        let signed_msg = SignedMessage::from_bytes(signed_message)
            .map_err(|_| anyhow::anyhow!("Invalid signed message format"))?;
        
        let message = pqcrypto_mldsa::mldsa44::open(&signed_msg, public_key)
            .map_err(|_| anyhow::anyhow!("Signature verification failed"))?;
        
        // Now construct ZK circuit to prove signature validity
        let config = CircuitConfig::standard_recursion_config();
        type C = PoseidonGoldilocksConfig;
        type F = <C as plonky2::plonk::config::GenericConfig<2>>::F;
        // ML-DSA-44 parameters: eta=2, gamma_1=2^17, gamma_2=(q-1)/88, tau=39, omega=80
        let (k, l, d, eta, tau, gamma_1, gamma_2, omega, c_tilde_bytes) = mldsa44_params();
        let verifier = MLDSAVerifier::<F, C, 2>::new(config, k, l, d, eta, tau, gamma_1, gamma_2, omega, c_tilde_bytes);
        
        let pk_bytes = public_key.as_bytes();
        let (_, sig_bytes, _) = self.get_signature_data(public_key, signed_message)?;
        
        let proof = verifier.generate_proof(pk_bytes, &sig_bytes, &message)
            .map_err(|e| anyhow::anyhow!("ZK proof generation failed: {}", e))?;
        
        verifier.circuit.verify(proof)
            .map_err(|e| anyhow::anyhow!("ZK proof verification failed: {}", e))?;
        
        Ok(message)
    }
    
    fn get_signature_data(
        &self,
        public_key: &Self::PublicKey,
        signed_message: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        let pk_bytes = public_key.as_bytes().to_vec();
        let signed_msg = SignedMessage::from_bytes(signed_message)
            .map_err(|_| anyhow::anyhow!("Invalid signed message format"))?;
        
        let original_message = pqcrypto_mldsa::mldsa44::open(&signed_msg, public_key)
            .map_err(|_| anyhow::anyhow!("Signature verification failed"))?;
        
        let signature_bytes = signed_message[..signed_message.len() - original_message.len()].to_vec();
        
        Ok((pk_bytes, signature_bytes, original_message))
    }
}

impl MLDSAVariant for MLDSA65 {
    type PublicKey = pqcrypto_mldsa::mldsa65::PublicKey;
    type SecretKey = pqcrypto_mldsa::mldsa65::SecretKey;
    
    fn security_level(&self) -> u8 { 3 }
    fn k(&self) -> usize { 6 }
    fn l(&self) -> usize { 5 }
    
    fn generate_keypair(&self) -> (Self::PublicKey, Self::SecretKey) {
        pqcrypto_mldsa::mldsa65::keypair()
    }
    
    fn sign_message(&self, secret_key: &Self::SecretKey, message: &[u8]) -> Result<Vec<u8>> {
        let signed_msg = pqcrypto_mldsa::mldsa65::sign(message, secret_key);
        Ok(signed_msg.as_bytes().to_vec())
    }
    
    fn verify_signature(&self, public_key: &Self::PublicKey, signed_message: &[u8]) -> Result<Vec<u8>> {
        // First do conventional verification to get the message
        let signed_msg = SignedMessage::from_bytes(signed_message)
            .map_err(|_| anyhow::anyhow!("Invalid signed message format"))?;
        
        let message = pqcrypto_mldsa::mldsa65::open(&signed_msg, public_key)
            .map_err(|_| anyhow::anyhow!("Signature verification failed"))?;
        
        // Now construct ZK circuit to prove signature validity
        let config = CircuitConfig::standard_recursion_config();
        type C = PoseidonGoldilocksConfig;
        type F = <C as plonky2::plonk::config::GenericConfig<2>>::F;
        // ML-DSA-65 parameters: eta=4, gamma_1=2^19, gamma_2=(q-1)/32, tau=49, omega=55
        let (k, l, d, eta, tau, gamma_1, gamma_2, omega, c_tilde_bytes) = mldsa65_params();
        let verifier = MLDSAVerifier::<F, C, 2>::new(config, k, l, d, eta, tau, gamma_1, gamma_2, omega, c_tilde_bytes);
        
        let pk_bytes = public_key.as_bytes();
        let (_, sig_bytes, _) = self.get_signature_data(public_key, signed_message)?;
        
        let proof = verifier.generate_proof(pk_bytes, &sig_bytes, &message)
            .map_err(|e| anyhow::anyhow!("ZK proof generation failed: {}", e))?;
        
        verifier.circuit.verify(proof)
            .map_err(|e| anyhow::anyhow!("ZK proof verification failed: {}", e))?;
        
        Ok(message)
    }
    
    fn get_signature_data(
        &self,
        public_key: &Self::PublicKey,
        signed_message: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        let pk_bytes = public_key.as_bytes().to_vec();
        let signed_msg = SignedMessage::from_bytes(signed_message)
            .map_err(|_| anyhow::anyhow!("Invalid signed message format"))?;
        
        let original_message = pqcrypto_mldsa::mldsa65::open(&signed_msg, public_key)
            .map_err(|_| anyhow::anyhow!("Signature verification failed"))?;
        
        let signature_bytes = signed_message[..signed_message.len() - original_message.len()].to_vec();
        
        Ok((pk_bytes, signature_bytes, original_message))
    }
}

impl MLDSAVariant for MLDSA87 {
    type PublicKey = pqcrypto_mldsa::mldsa87::PublicKey;
    type SecretKey = pqcrypto_mldsa::mldsa87::SecretKey;
    
    fn security_level(&self) -> u8 { 5 }
    fn k(&self) -> usize { 8 }
    fn l(&self) -> usize { 7 }
    
    fn generate_keypair(&self) -> (Self::PublicKey, Self::SecretKey) {
        pqcrypto_mldsa::mldsa87::keypair()
    }
    
    fn sign_message(&self, secret_key: &Self::SecretKey, message: &[u8]) -> Result<Vec<u8>> {
        let signed_msg = pqcrypto_mldsa::mldsa87::sign(message, secret_key);
        Ok(signed_msg.as_bytes().to_vec())
    }
    
    fn verify_signature(&self, public_key: &Self::PublicKey, signed_message: &[u8]) -> Result<Vec<u8>> {
        // First do conventional verification to get the message
        let signed_msg = SignedMessage::from_bytes(signed_message)
            .map_err(|_| anyhow::anyhow!("Invalid signed message format"))?;
        
        let message = pqcrypto_mldsa::mldsa87::open(&signed_msg, public_key)
            .map_err(|_| anyhow::anyhow!("Signature verification failed"))?;
        
        // Now construct ZK circuit to prove signature validity
        let config = CircuitConfig::standard_recursion_config();
        type C = PoseidonGoldilocksConfig;
        type F = <C as plonky2::plonk::config::GenericConfig<2>>::F;
        // ML-DSA-87 parameters: eta=2, gamma_1=2^19, gamma_2=(q-1)/32, tau=60, omega=75
        let (k, l, d, eta, tau, gamma_1, gamma_2, omega, c_tilde_bytes) = mldsa87_params();
        let verifier = MLDSAVerifier::<F, C, 2>::new(config, k, l, d, eta, tau, gamma_1, gamma_2, omega, c_tilde_bytes);
        
        let pk_bytes = public_key.as_bytes();
        let (_, sig_bytes, _) = self.get_signature_data(public_key, signed_message)?;
        
        let proof = verifier.generate_proof(pk_bytes, &sig_bytes, &message)
            .map_err(|e| anyhow::anyhow!("ZK proof generation failed: {}", e))?;
        
        verifier.circuit.verify(proof)
            .map_err(|e| anyhow::anyhow!("ZK proof verification failed: {}", e))?;
        
        Ok(message)
    }
    
    fn get_signature_data(
        &self,
        public_key: &Self::PublicKey,
        signed_message: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        let pk_bytes = public_key.as_bytes().to_vec();
        let signed_msg = SignedMessage::from_bytes(signed_message)
            .map_err(|_| anyhow::anyhow!("Invalid signed message format"))?;
        
        let original_message = pqcrypto_mldsa::mldsa87::open(&signed_msg, public_key)
            .map_err(|_| anyhow::anyhow!("Signature verification failed"))?;
        
        let signature_bytes = signed_message[..signed_message.len() - original_message.len()].to_vec();
        
        Ok((pk_bytes, signature_bytes, original_message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mldsa44_trait() {
        let variant = MLDSA44;
        assert_eq!(variant.security_level(), 2);
        assert_eq!(variant.k(), 4);
        assert_eq!(variant.l(), 4);
        
        let (pk, sk) = variant.generate_keypair();
        let message = b"Test message for ML-DSA-44";
        
        let signed_msg = variant.sign_message(&sk, message).unwrap();
        let verified_msg = variant.verify_signature(&pk, &signed_msg).unwrap();
        assert_eq!(message, verified_msg.as_slice());
        
        let (pk_bytes, sig_bytes, extracted_msg) = 
            variant.get_signature_data(&pk, &signed_msg).unwrap();
        assert_eq!(message, extracted_msg.as_slice());
        assert!(!pk_bytes.is_empty());
        assert!(!sig_bytes.is_empty());
    }

    #[test]
    fn test_mldsa65_trait() {
        let variant = MLDSA65;
        assert_eq!(variant.security_level(), 3);
        assert_eq!(variant.k(), 6);
        assert_eq!(variant.l(), 5);
        
        let (pk, sk) = variant.generate_keypair();
        let message = b"Test message for ML-DSA-65";
        
        let signed_msg = variant.sign_message(&sk, message).unwrap();
        let verified_msg = variant.verify_signature(&pk, &signed_msg).unwrap();
        assert_eq!(message, verified_msg.as_slice());
        
        let (pk_bytes, sig_bytes, extracted_msg) = 
            variant.get_signature_data(&pk, &signed_msg).unwrap();
        assert_eq!(message, extracted_msg.as_slice());
        assert!(!pk_bytes.is_empty());
        assert!(!sig_bytes.is_empty());
    }

    #[test]
    fn test_mldsa87_trait() {
        let variant = MLDSA87;
        assert_eq!(variant.security_level(), 5);
        assert_eq!(variant.k(), 8);
        assert_eq!(variant.l(), 7);
        
        let (pk, sk) = variant.generate_keypair();
        let message = b"Test message for ML-DSA-87";
        
        let signed_msg = variant.sign_message(&sk, message).unwrap();
        let verified_msg = variant.verify_signature(&pk, &signed_msg).unwrap();
        assert_eq!(message, verified_msg.as_slice());
        
        let (pk_bytes, sig_bytes, extracted_msg) = 
            variant.get_signature_data(&pk, &signed_msg).unwrap();
        assert_eq!(message, extracted_msg.as_slice());
        assert!(!pk_bytes.is_empty());
        assert!(!sig_bytes.is_empty());
    }

    #[test]
    fn test_all_variants_with_same_message() {
        let message = b"Cross-variant compatibility test";
        
        // Test each variant independently - they currently use the same underlying implementation
        // but have different logical parameters
        let variant44 = MLDSA44;
        let (pk44, sk44) = variant44.generate_keypair();
        let signed44 = variant44.sign_message(&sk44, message).unwrap();
        let verified44 = variant44.verify_signature(&pk44, &signed44).unwrap();
        assert_eq!(message, verified44.as_slice());
        
        let variant65 = MLDSA65;
        let (pk65, sk65) = variant65.generate_keypair();
        let signed65 = variant65.sign_message(&sk65, message).unwrap();
        let verified65 = variant65.verify_signature(&pk65, &signed65).unwrap();
        assert_eq!(message, verified65.as_slice());
        
        let variant87 = MLDSA87;
        let (pk87, sk87) = variant87.generate_keypair();
        let signed87 = variant87.sign_message(&sk87, message).unwrap();
        let verified87 = variant87.verify_signature(&pk87, &signed87).unwrap();
        assert_eq!(message, verified87.as_slice());
        
        // Verify that each variant reports correct parameters
        assert_eq!(variant44.security_level(), 2);
        assert_eq!(variant65.security_level(), 3);
        assert_eq!(variant87.security_level(), 5);
    }
    
    #[test]
    fn test_variant_parameters() {
        let variant44 = MLDSA44;
        let variant65 = MLDSA65;
        let variant87 = MLDSA87;
        
        // Test ML-DSA-44 parameters
        assert_eq!(variant44.security_level(), 2);
        assert_eq!(variant44.k(), 4);
        assert_eq!(variant44.l(), 4);
        
        // Test ML-DSA-65 parameters
        assert_eq!(variant65.security_level(), 3);
        assert_eq!(variant65.k(), 6);
        assert_eq!(variant65.l(), 5);
        
        // Test ML-DSA-87 parameters
        assert_eq!(variant87.security_level(), 5);
        assert_eq!(variant87.k(), 8);
        assert_eq!(variant87.l(), 7);
    }

    #[test]
    fn test_variants_produce_different_sizes() {
        let message = b"Test message for size comparison";
        
        // Test each variant and collect sizes
        let variant44 = MLDSA44;
        let (pk44, sk44) = variant44.generate_keypair();
        let signed44 = variant44.sign_message(&sk44, message).unwrap();
        let (pk44_bytes, sig44_bytes, _) = variant44.get_signature_data(&pk44, &signed44).unwrap();
        
        let variant65 = MLDSA65;
        let (pk65, sk65) = variant65.generate_keypair();
        let signed65 = variant65.sign_message(&sk65, message).unwrap();
        let (pk65_bytes, sig65_bytes, _) = variant65.get_signature_data(&pk65, &signed65).unwrap();
        
        let variant87 = MLDSA87;
        let (pk87, sk87) = variant87.generate_keypair();
        let signed87 = variant87.sign_message(&sk87, message).unwrap();
        let (pk87_bytes, sig87_bytes, _) = variant87.get_signature_data(&pk87, &signed87).unwrap();
        
        println!("Trait interface sizes:");
        println!("  ML-DSA-44: pk={} bytes, sig={} bytes", pk44_bytes.len(), sig44_bytes.len());
        println!("  ML-DSA-65: pk={} bytes, sig={} bytes", pk65_bytes.len(), sig65_bytes.len());
        println!("  ML-DSA-87: pk={} bytes, sig={} bytes", pk87_bytes.len(), sig87_bytes.len());
        
        // Verify they are all different sizes
        assert_ne!(pk44_bytes.len(), pk65_bytes.len(), "ML-DSA-44 and ML-DSA-65 should have different public key sizes");
        assert_ne!(pk65_bytes.len(), pk87_bytes.len(), "ML-DSA-65 and ML-DSA-87 should have different public key sizes");
        assert_ne!(pk44_bytes.len(), pk87_bytes.len(), "ML-DSA-44 and ML-DSA-87 should have different public key sizes");
        
        assert_ne!(sig44_bytes.len(), sig65_bytes.len(), "ML-DSA-44 and ML-DSA-65 should have different signature sizes");
        assert_ne!(sig65_bytes.len(), sig87_bytes.len(), "ML-DSA-65 and ML-DSA-87 should have different signature sizes");
        assert_ne!(sig44_bytes.len(), sig87_bytes.len(), "ML-DSA-44 and ML-DSA-87 should have different signature sizes");
        
        // Verify expected sizes match the actual variant implementations
        assert_eq!(pk44_bytes.len(), 1312, "ML-DSA-44 public key should be 1312 bytes");
        assert_eq!(pk65_bytes.len(), 1952, "ML-DSA-65 public key should be 1952 bytes");
        assert_eq!(pk87_bytes.len(), 2592, "ML-DSA-87 public key should be 2592 bytes");
    }
}