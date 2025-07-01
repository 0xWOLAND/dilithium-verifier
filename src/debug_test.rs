#[cfg(test)]
mod tests {
    use crate::complete_verifier::CompleteMLDSAVerifierCircuit;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use plonky2::plonk::circuit_data::CircuitConfig;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as plonky2::plonk::config::GenericConfig<D>>::F;

    #[test]
    fn test_simple_circuit_construction() {
        // Test with very simple parameters to see if circuit builds at all
        let config = CircuitConfig::standard_recursion_config();
        
        let k = 1; // Minimal size
        let l = 1;
        let eta = 2;
        let gamma_1 = 1000; // Small gamma_1 
        let gamma_2 = 500;  // Small gamma_2
        let tau = 4;
        let omega = 10;
        
        println!("Creating circuit with small parameters...");
        let result = std::panic::catch_unwind(|| {
            CompleteMLDSAVerifierCircuit::<F, C, D>::new(
                config, k, l, eta, gamma_1, gamma_2, tau, omega
            )
        });
        
        match result {
            Ok(verifier) => {
                println!("Circuit construction succeeded!");
                
                // Test proof generation with small test data
                let pk_bytes = vec![42u8; 32 + k * 256 * 2];
                let sig_bytes = vec![123u8; 32 + l * 256 * 3 + k * 256];
                let message = b"test";
                
                println!("Testing proof generation...");
                let proof_result = verifier.generate_proof(&pk_bytes, &sig_bytes, message);
                
                match proof_result {
                    Ok(_proof) => {
                        println!("Proof generation succeeded!");
                    },
                    Err(e) => {
                        println!("Proof generation failed: {:?}", e);
                        // This is expected to fail for now, but let's see the error
                    }
                }
            },
            Err(e) => {
                println!("Circuit construction failed: {:?}", e);
                panic!("Circuit construction should not fail with small parameters");
            }
        }
    }
}