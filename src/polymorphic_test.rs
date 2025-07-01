#[cfg(test)]
mod tests {
    use crate::mldsa_trait::{MLDSAVariant, MLDSA44, MLDSA65, MLDSA87};
    use anyhow::Result;

    #[test]
    fn test_variant_polymorphism() -> Result<()> {
        let message = b"Polymorphic test message";
        
        // Function that works with any ML-DSA variant
        fn sign_and_verify<V: MLDSAVariant>(variant: V, msg: &[u8]) -> Result<(usize, usize)> {
            let (pk, sk) = variant.generate_keypair();
            let signed_msg = variant.sign_message(&sk, msg)?;
            let verified_msg = variant.verify_signature(&pk, &signed_msg)?;
            
            assert_eq!(msg, verified_msg.as_slice());
            
            let (pk_bytes, sig_bytes, _) = variant.get_signature_data(&pk, &signed_msg)?;
            Ok((pk_bytes.len(), sig_bytes.len()))
        }
        
        // Test each variant through the same interface
        let (pk44_len, sig44_len) = sign_and_verify(MLDSA44, message)?;
        let (pk65_len, sig65_len) = sign_and_verify(MLDSA65, message)?;
        let (pk87_len, sig87_len) = sign_and_verify(MLDSA87, message)?;
        
        println!("Polymorphic test results:");
        println!("  ML-DSA-44: pk={} bytes, sig={} bytes", pk44_len, sig44_len);
        println!("  ML-DSA-65: pk={} bytes, sig={} bytes", pk65_len, sig65_len);
        println!("  ML-DSA-87: pk={} bytes, sig={} bytes", pk87_len, sig87_len);
        
        Ok(())
    }
}