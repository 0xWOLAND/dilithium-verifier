#[cfg(test)]
mod tests {
    use crate::simple_verifier::SimpleMLDSAVerifierCircuit;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use plonky2::plonk::circuit_data::CircuitConfig;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as plonky2::plonk::config::GenericConfig<D>>::F;

    #[test]
    fn test_simple_range_check_only() {
        // Test with just range checks, no complex operations
        let config = CircuitConfig::standard_recursion_config();
        let verifier = SimpleMLDSAVerifierCircuit::<F, C, D>::new(config, 1, 1);
        
        let pk_bytes = vec![42u8; 64];
        let sig_bytes = vec![123u8; 64];
        let message = b"test";
        
        let proof_result = verifier.generate_proof(&pk_bytes, &sig_bytes, message);
        assert!(proof_result.is_ok(), "Simple range check should work: {:?}", proof_result.err());
        
        let proof = proof_result.unwrap();
        let verify_result = verifier.circuit.verify(proof);
        assert!(verify_result.is_ok(), "Simple proof verification should work: {:?}", verify_result.err());
    }

    #[test] 
    fn test_gradual_increase_simple() {
        let configs = vec![
            (1, 1),
            (2, 2),
            (4, 4),
        ];
        
        for (k, l) in configs {
            println!("Testing simple circuit with k={}, l={}", k, l);
            
            let config = CircuitConfig::standard_recursion_config();
            let verifier = SimpleMLDSAVerifierCircuit::<F, C, D>::new(config, k, l);
            
            let pk_bytes = vec![42u8; 64];
            let sig_bytes = vec![123u8; 64];
            let message = b"test";
            
            let proof_result = verifier.generate_proof(&pk_bytes, &sig_bytes, message);
            
            match proof_result {
                Ok(proof) => {
                    println!("  ✓ Simple circuit k={}, l={} succeeded", k, l);
                    match verifier.circuit.verify(proof) {
                        Ok(_) => println!("  ✓ Verification succeeded"),
                        Err(e) => println!("  ✗ Verification failed: {:?}", e),
                    }
                }
                Err(e) => {
                    println!("  ✗ Circuit failed k={}, l={}: {:?}", k, l, e);
                    if e.to_string().contains("Partition containing Wire") {
                        panic!("Wire conflict in simple circuit at k={}, l={}", k, l);
                    }
                }
            }
        }
    }
}