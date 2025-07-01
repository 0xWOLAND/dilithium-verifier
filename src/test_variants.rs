// Test to see what ML-DSA variants are actually available
use pqcrypto_mldsa::{mldsa44, mldsa65, mldsa87};
use pqcrypto_traits::sign::{PublicKey, SecretKey, SignedMessage};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mldsa44_availability() {
        let (pk, sk) = mldsa44::keypair();
        let message = b"Test ML-DSA-44";
        let signed_msg = mldsa44::sign(message, &sk);
        let verified_msg = mldsa44::open(&signed_msg, &pk).unwrap();
        assert_eq!(message, verified_msg.as_slice());
        
        println!("ML-DSA-44: pk={} bytes, sig={} bytes", 
                 pk.as_bytes().len(), 
                 signed_msg.as_bytes().len());
    }

    #[test]
    fn test_mldsa65_availability() {
        let (pk, sk) = mldsa65::keypair();
        let message = b"Test ML-DSA-65";
        let signed_msg = mldsa65::sign(message, &sk);
        let verified_msg = mldsa65::open(&signed_msg, &pk).unwrap();
        assert_eq!(message, verified_msg.as_slice());
        
        println!("ML-DSA-65: pk={} bytes, sig={} bytes", 
                 pk.as_bytes().len(), 
                 signed_msg.as_bytes().len());
    }

    #[test]
    fn test_mldsa87_availability() {
        let (pk, sk) = mldsa87::keypair();
        let message = b"Test ML-DSA-87";
        let signed_msg = mldsa87::sign(message, &sk);
        let verified_msg = mldsa87::open(&signed_msg, &pk).unwrap();
        assert_eq!(message, verified_msg.as_slice());
        
        println!("ML-DSA-87: pk={} bytes, sig={} bytes", 
                 pk.as_bytes().len(), 
                 signed_msg.as_bytes().len());
    }

    #[test]
    fn test_variants_produce_different_sizes() {
        let message = b"Size comparison test";
        
        let (pk44, sk44) = mldsa44::keypair();
        let signed44 = mldsa44::sign(message, &sk44);
        
        let (pk65, sk65) = mldsa65::keypair();
        let signed65 = mldsa65::sign(message, &sk65);
        
        let (pk87, sk87) = mldsa87::keypair();
        let signed87 = mldsa87::sign(message, &sk87);
        
        println!("Key and signature sizes:");
        println!("  ML-DSA-44: pk={} sk={} sig={}", 
                 pk44.as_bytes().len(), 
                 sk44.as_bytes().len(),
                 signed44.as_bytes().len());
        println!("  ML-DSA-65: pk={} sk={} sig={}", 
                 pk65.as_bytes().len(), 
                 sk65.as_bytes().len(),
                 signed65.as_bytes().len());
        println!("  ML-DSA-87: pk={} sk={} sig={}", 
                 pk87.as_bytes().len(), 
                 sk87.as_bytes().len(),
                 signed87.as_bytes().len());
        
        // They should have different sizes
        let pk44_len = pk44.as_bytes().len();
        let pk65_len = pk65.as_bytes().len();
        let pk87_len = pk87.as_bytes().len();
        
        assert!(pk44_len != pk65_len || pk65_len != pk87_len, 
                "Different variants should have different key/signature sizes");
    }
}