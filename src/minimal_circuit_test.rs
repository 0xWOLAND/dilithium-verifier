#[cfg(test)]
mod tests {
    use crate::verifier::MLDSAVerifierCircuit;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::field::types::Field;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as plonky2::plonk::config::GenericConfig<D>>::F;

    #[test]
    fn test_minimal_mldsa_circuit() {
        // Test with minimal parameters to isolate the wire conflict
        let config = CircuitConfig::standard_recursion_config();
        
        // Use very small k=1, l=1 to minimize the circuit
        let verifier = MLDSAVerifierCircuit::<F, C, D>::new(config, 1, 1);
        
        // Create minimal test data
        let pk_bytes = vec![42u8; 32 + 1 * 256 * 2]; // SEEDBYTES + k * N * 2
        let sig_bytes = vec![123u8; 32 + 1 * 256 * 3 + 1 * 256]; // SEEDBYTES + l * N * 3 + k * N
        let message = b"test";
        
        let proof_result = verifier.generate_proof(&pk_bytes, &sig_bytes, message);
        
        // This should succeed with minimal parameters
        assert!(proof_result.is_ok(), "Minimal ML-DSA circuit should not have wire conflicts");
        
        let proof = proof_result.unwrap();
        let verify_result = verifier.circuit.verify(proof);
        assert!(verify_result.is_ok(), "Proof verification should succeed");
    }

    #[test]
    fn test_gradual_increase_parameters() {
        // Test gradually increasing parameters to find where conflicts start
        let configs = vec![
            (1, 1, "1x1"),
            (2, 2, "2x2"), 
            (4, 4, "4x4"), // This is what ML-DSA-44 uses
        ];
        
        for (k, l, name) in configs {
            println!("Testing ML-DSA circuit with k={}, l={} ({})", k, l, name);
            
            let config = CircuitConfig::standard_recursion_config();
            let verifier = MLDSAVerifierCircuit::<F, C, D>::new(config, k, l);
            
            // Create appropriately sized test data
            let pk_bytes = vec![42u8; 32 + k * 256 * 2]; 
            let sig_bytes = vec![123u8; 32 + l * 256 * 3 + k * 256];
            let message = b"test";
            
            let proof_result = verifier.generate_proof(&pk_bytes, &sig_bytes, message);
            
            match proof_result {
                Ok(proof) => {
                    println!("  ✓ Circuit construction and proof generation succeeded for {}", name);
                    match verifier.circuit.verify(proof) {
                        Ok(_) => println!("  ✓ Proof verification succeeded for {}", name),
                        Err(e) => println!("  ✗ Proof verification failed for {}: {:?}", name, e),
                    }
                }
                Err(e) => {
                    println!("  ✗ Proof generation failed for {}: {:?}", name, e);
                    
                    // For debugging, let's see if the error mentions wire conflicts
                    if e.to_string().contains("Partition containing Wire") {
                        println!("    -> This is the wire conflict we're looking for!");
                        panic!("Wire conflict found at k={}, l={}", k, l);
                    }
                }
            }
        }
    }
}