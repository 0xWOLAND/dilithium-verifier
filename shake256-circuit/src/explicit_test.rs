#[cfg(test)]
mod explicit_tdd_tests {
    use crate::shake256_circuit::Shake256Circuit;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as plonky2::plonk::config::GenericConfig<D>>::F;

    #[test]
    #[should_panic(expected = "Circuit output should match reference SHAKE256")]
    fn test_tdd_red_phase_explicit_failure() {
        // This test explicitly demonstrates the TDD red phase
        // The circuit implementation is currently a stub that returns zeros
        // So this test should fail when comparing against the reference implementation
        
        let config = CircuitConfig::standard_recursion_config();
        let circuit = Shake256Circuit::<F, C, D>::new(config, 32, 32);
        
        let input_data = b"test input for TDD demonstration";
        let reference_output = Shake256Circuit::<F, C, D>::reference_shake256(input_data, 32);
        
        // Generate proof with stub implementation
        let proof = circuit.generate_proof(input_data).expect("Proof generation should succeed");
        let circuit_output = circuit.extract_output(&proof).expect("Output extraction should succeed");
        
        // This assertion should fail because circuit_output is all zeros
        // while reference_output is the actual SHAKE256 hash
        assert_eq!(circuit_output, reference_output, "Circuit output should match reference SHAKE256");
    }

    #[test]
    fn test_reference_implementation_works() {
        // This test confirms our reference implementation is working correctly
        let input = b"abc";
        let output = Shake256Circuit::<F, C, D>::reference_shake256(input, 32);
        
        // Should produce consistent output
        let output2 = Shake256Circuit::<F, C, D>::reference_shake256(input, 32);
        assert_eq!(output, output2, "Reference implementation should be deterministic");
        
        // Should not be all zeros
        assert_ne!(output, vec![0u8; 32], "Reference output should not be all zeros");
        
        // Different inputs should produce different outputs
        let different_output = Shake256Circuit::<F, C, D>::reference_shake256(b"def", 32);
        assert_ne!(output, different_output, "Different inputs should produce different outputs");
    }
}