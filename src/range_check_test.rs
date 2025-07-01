#[cfg(test)]
mod tests {
    use super::*;
    use crate::verifier::MLDSAVerifierCircuit;
    use crate::types::PolynomialTarget;
    use crate::constants::*;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::field::types::Field;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as plonky2::plonk::config::GenericConfig<D>>::F;

    #[test]
    fn test_range_check_single_coefficient() {
        // Test that a single coefficient can be range-checked without conflicts
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        // Create a single coefficient target
        let coeff = builder.add_virtual_target();
        
        // Apply range check - this should work for a single coefficient
        let range_bits = 18;
        builder.range_check(coeff, range_bits);
        
        // Build circuit
        let circuit = builder.build::<C>();
        
        // Create witness with valid coefficient value
        let mut pw = PartialWitness::new();
        let valid_value = 1000u64; // Well within γ₁ = 131072
        pw.set_target(coeff, F::from_canonical_u64(valid_value));
        
        // This should succeed
        let proof = circuit.prove(pw).expect("Single coefficient range check should work");
        circuit.verify(proof).expect("Proof should verify");
    }

    #[test]
    fn test_range_check_multiple_coefficients_separate_targets() {
        // Test multiple coefficients with separate targets (no reuse)
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        let num_coeffs = 4; // Test with a small number first
        let mut coeffs = Vec::new();
        
        for i in 0..num_coeffs {
            let coeff = builder.add_virtual_target();
            let range_bits = 18;
            builder.range_check(coeff, range_bits);
            coeffs.push(coeff);
        }
        
        let circuit = builder.build::<C>();
        
        let mut pw = PartialWitness::new();
        for (i, &coeff) in coeffs.iter().enumerate() {
            let valid_value = (1000 + i) as u64;
            pw.set_target(coeff, F::from_canonical_u64(valid_value));
        }
        
        let proof = circuit.prove(pw).expect("Multiple separate coefficients should work");
        circuit.verify(proof).expect("Proof should verify");
    }

    #[test]
    fn test_range_check_with_intermediate_targets() {
        // Test using intermediate targets to avoid wire conflicts
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        let num_coeffs = 4;
        let mut source_coeffs = Vec::new();
        
        for _i in 0..num_coeffs {
            let source_coeff = builder.add_virtual_target();
            
            // Create intermediate target for range checking
            let intermediate = builder.add_virtual_target();
            builder.connect(intermediate, source_coeff);
            
            let range_bits = 18;
            builder.range_check(intermediate, range_bits);
            
            source_coeffs.push(source_coeff);
        }
        
        let circuit = builder.build::<C>();
        
        let mut pw = PartialWitness::new();
        for (i, &coeff) in source_coeffs.iter().enumerate() {
            let valid_value = (1000 + i) as u64;
            pw.set_target(coeff, F::from_canonical_u64(valid_value));
        }
        
        let proof = circuit.prove(pw).expect("Intermediate targets should work");
        circuit.verify(proof).expect("Proof should verify");
    }

    #[test]
    #[should_panic(expected = "Partition containing Wire")]
    fn test_range_check_wire_conflict_reproduction() {
        // This test should reproduce the wire conflict error
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        let source_coeff = builder.add_virtual_target();
        
        // Try to range check the same target multiple times - this should cause conflict
        let range_bits = 18;
        builder.range_check(source_coeff, range_bits);
        builder.range_check(source_coeff, range_bits); // This should cause the conflict
        
        let circuit = builder.build::<C>();
        
        let mut pw = PartialWitness::new();
        pw.set_target(source_coeff, F::from_canonical_u64(1000));
        
        // This should panic with wire conflict
        let _proof = circuit.prove(pw);
    }
}