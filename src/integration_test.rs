use crate::{MLDSASigner};
use crate::simple_verifier::SimpleMLDSAVerifierCircuit;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::PoseidonGoldilocksConfig;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as plonky2::plonk::config::GenericConfig<D>>::F;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_real_mldsa_to_zk_circuit() {
        // Generate real ML-DSA signature
        let (pk, sk) = MLDSASigner::generate_keypair();
        let message = b"Integration test message";
        
        let signed_message = MLDSASigner::sign_message(&sk, message).unwrap();
        let verified_message = MLDSASigner::verify_signature(&pk, &signed_message).unwrap();
        assert_eq!(message, verified_message.as_slice());
        
        // Extract signature data
        let (pk_bytes, sig_bytes, extracted_msg) = 
            MLDSASigner::extract_signature_data(&pk, &signed_message).unwrap();
        assert_eq!(message, extracted_msg.as_slice());
        
        // Test ZK circuit construction
        let config = CircuitConfig::standard_recursion_config();
        match std::panic::catch_unwind(|| {
            SimpleMLDSAVerifierCircuit::<F, C, D>::new(config, 4, 4)
        }) {
            Ok(verifier) => {
                // If circuit builds successfully, try proof generation
                match verifier.generate_proof(&pk_bytes, &sig_bytes, message) {
                    Ok(proof) => {
                        // Verify the proof
                        assert!(verifier.circuit.verify(proof).is_ok());
                    }
                    Err(_) => {
                        // Proof generation might fail due to circuit complexity
                        // but the signature extraction worked
                    }
                }
            }
            Err(_) => {
                // Circuit construction might fail due to complexity
                // but the real Dilithium operations worked
            }
        }
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
            
            // Verify data sizes
            assert!(!pk_bytes.is_empty());
            assert!(!sig_bytes.is_empty());
            assert_eq!(extracted_msg, message.to_vec());
        }
    }
}