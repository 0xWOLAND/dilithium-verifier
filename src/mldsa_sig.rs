use pqcrypto_mldsa::mldsa65::*;
use pqcrypto_traits::sign::{PublicKey, SignedMessage};
use anyhow::Result;

pub struct MLDSASigner;

impl MLDSASigner {
    pub fn generate_keypair() -> (pqcrypto_mldsa::mldsa65::PublicKey, pqcrypto_mldsa::mldsa65::SecretKey) {
        keypair()
    }
    
    pub fn sign_message(
        secret_key: &pqcrypto_mldsa::mldsa65::SecretKey,
        message: &[u8],
    ) -> Result<Vec<u8>> {
        let signed_msg = sign(message, secret_key);
        Ok(signed_msg.as_bytes().to_vec())
    }
    
    pub fn verify_signature(
        public_key: &pqcrypto_mldsa::mldsa65::PublicKey,
        signed_message: &[u8],
    ) -> Result<Vec<u8>> {
        let signed_msg = SignedMessage::from_bytes(signed_message)
            .map_err(|_| anyhow::anyhow!("Invalid signed message format"))?;
        
        let message = open(&signed_msg, public_key)
            .map_err(|_| anyhow::anyhow!("Signature verification failed"))?;
        
        Ok(message)
    }
    
    pub fn extract_signature_data(
        public_key: &pqcrypto_mldsa::mldsa65::PublicKey,
        signed_message: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        let pk_bytes = public_key.as_bytes().to_vec();
        let signed_msg = SignedMessage::from_bytes(signed_message)
            .map_err(|_| anyhow::anyhow!("Invalid signed message format"))?;
        
        let original_message = open(&signed_msg, public_key)
            .map_err(|_| anyhow::anyhow!("Signature verification failed"))?;
        
        let signature_bytes = signed_message[..signed_message.len() - original_message.len()].to_vec();
        
        Ok((pk_bytes, signature_bytes, original_message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mldsa_sign_verify() {
        let (pk, sk) = MLDSASigner::generate_keypair();
        let message = b"Hello, ML-DSA ZK Verifier!";
        
        let signed_msg = MLDSASigner::sign_message(&sk, message).unwrap();
        let verified_msg = MLDSASigner::verify_signature(&pk, &signed_msg).unwrap();
        
        assert_eq!(message, verified_msg.as_slice());
    }
    
    #[test]
    fn test_extract_signature_data() {
        let (pk, sk) = MLDSASigner::generate_keypair();
        let message = b"Test message for ML-DSA data extraction";
        
        let signed_msg = MLDSASigner::sign_message(&sk, message).unwrap();
        let (pk_bytes, sig_bytes, extracted_msg) = 
            MLDSASigner::extract_signature_data(&pk, &signed_msg).unwrap();
        
        assert_eq!(message, extracted_msg.as_slice());
        assert!(!pk_bytes.is_empty());
        assert!(!sig_bytes.is_empty());
        assert_eq!(extracted_msg, message.to_vec());
    }
    
    #[test]
    fn test_multiple_mldsa_messages() {
        let (pk, sk) = MLDSASigner::generate_keypair();
        
        let messages = vec![
            b"First ML-DSA test message".as_slice(),
            b"Second ML-DSA test message".as_slice(), 
            b"Third ML-DSA test message with more content".as_slice(),
        ];
        
        for message in messages {
            let signed_message = MLDSASigner::sign_message(&sk, message).unwrap();
            let verified_message = MLDSASigner::verify_signature(&pk, &signed_message).unwrap();
            assert_eq!(message, verified_message.as_slice());
            
            let (pk_bytes, sig_bytes, extracted_msg) = 
                MLDSASigner::extract_signature_data(&pk, &signed_message).unwrap();
            assert_eq!(message, extracted_msg.as_slice());
            assert!(!pk_bytes.is_empty());
            assert!(!sig_bytes.is_empty());
        }
    }
}