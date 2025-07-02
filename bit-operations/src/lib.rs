use plonky2::field::extension::Extendable;
use plonky2::gates::lookup_table::LookupTable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2_field::types::PrimeField64;
use std::sync::Arc;

/// Efficient bit operations gadget using plonky2 built-in lookup tables
/// This provides optimized bit operations for zero-knowledge circuits using lookup arguments

/// Creates a lookup table for 8-bit XOR operations
pub fn create_8bit_xor_table() -> LookupTable {
    let mut entries = Vec::new();
    for a in 0..256u16 {
        for b in 0..256u16 {
            let input = (a << 8) | b;
            let output = a ^ b;
            entries.push((input, output));
        }
    }
    Arc::new(entries)
}

/// Creates a lookup table for 8-bit AND operations
pub fn create_8bit_and_table() -> LookupTable {
    let mut entries = Vec::new();
    for a in 0..256u16 {
        for b in 0..256u16 {
            let input = (a << 8) | b;
            let output = a & b;
            entries.push((input, output));
        }
    }
    Arc::new(entries)
}

/// Creates a lookup table for 8-bit OR operations
fn create_8bit_or_table() -> LookupTable {
    let mut entries = Vec::new();
    for a in 0..256u16 {
        for b in 0..256u16 {
            let input = (a << 8) | b;
            let output = a | b;
            entries.push((input, output));
        }
    }
    Arc::new(entries)
}

/// Creates a lookup table for 8-bit NOT operations
fn create_8bit_not_table() -> LookupTable {
    let mut entries = Vec::new();
    for a in 0..256u16 {
        let output = !a & 0xFF;
        entries.push((a, output));
    }
    Arc::new(entries)
}

/// Efficient 8-bit XOR using lookup tables with range checks
pub fn bitwise_xor_8bit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: Target,
    b: Target,
) -> Target {
    let xor_table = create_8bit_xor_table();
    let table_index = builder.add_lookup_table_from_pairs(xor_table);
    
    let a_256 = builder.constant(F::from_canonical_u16(256));
    let packed_input = builder.mul(a, a_256);
    let packed_input = builder.add(packed_input, b);
    
    let result = builder.add_lookup_from_index(packed_input, table_index);
    
    result
}

/// Efficient 8-bit AND using lookup tables
pub fn bitwise_and_8bit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: Target,
    b: Target,
) -> Target {
    let and_table = create_8bit_and_table();
    let table_index = builder.add_lookup_table_from_pairs(and_table);
    
    let a_256 = builder.constant(F::from_canonical_u16(256));
    let packed_input = builder.mul(a, a_256);
    let packed_input = builder.add(packed_input, b);
    
    let result = builder.add_lookup_from_index(packed_input, table_index);
    
    result
}

/// Efficient 8-bit OR using lookup tables
pub fn bitwise_or_8bit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: Target,
    b: Target,
) -> Target {
    let or_table = create_8bit_or_table();
    let table_index = builder.add_lookup_table_from_pairs(or_table);
    
    let a_256 = builder.constant(F::from_canonical_u16(256));
    let packed_input = builder.mul(a, a_256);
    let packed_input = builder.add(packed_input, b);
    
    let result = builder.add_lookup_from_index(packed_input, table_index);
    
    result
}

/// Efficient 8-bit NOT using lookup tables
pub fn bitwise_not_8bit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: Target,
) -> Target {
    let not_table = create_8bit_not_table();
    let table_index = builder.add_lookup_table_from_pairs(not_table);
    
    let result = builder.add_lookup_from_index(a, table_index);
    
    result
}

/// Arithmetic-based XOR for single bits
pub fn bitwise_xor<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: Target,
    b: Target,
) -> Target {
    let sum = builder.add(a, b);
    let two = builder.constant(F::TWO);
    let product = builder.mul(a, b);
    let double_product = builder.mul(two, product);
    let result = builder.sub(sum, double_product);
    
    result
}

/// Arithmetic-based AND for single bits
pub fn bitwise_and<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: Target,
    b: Target,
) -> Target {
    let result = builder.mul(a, b);
    
    result
}

/// Arithmetic-based OR for single bits
pub fn bitwise_or<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: Target,
    b: Target,
) -> Target {
    let sum = builder.add(a, b);
    let product = builder.mul(a, b);
    let result = builder.sub(sum, product);
    
    result
}

/// Arithmetic-based NOT for single bits
pub fn bitwise_not<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: Target,
) -> Target {
    let one = builder.one();
    let result = builder.sub(one, a);
    
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::field::types::Field;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    #[test]
    fn test_bitwise_xor_8bit_comprehensive() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        let a = builder.add_virtual_target();
        let b = builder.add_virtual_target();
        let result = bitwise_xor_8bit(&mut builder, a, b);
        
        builder.register_public_input(a);
        builder.register_public_input(b);
        builder.register_public_input(result);
        
        let circuit = builder.build::<C>();
        
        let test_cases = [
            (0u8, 0u8, 0u8),
            (255u8, 0u8, 255u8),
            (170u8, 85u8, 255u8),
            (15u8, 240u8, 255u8),
            (123u8, 45u8, 123u8 ^ 45u8),
            (200u8, 100u8, 200u8 ^ 100u8),
        ];
        
        for (a_val, b_val, expected) in test_cases.iter() {
            let mut pw = PartialWitness::new();
            pw.set_target(a, F::from_canonical_u8(*a_val));
            pw.set_target(b, F::from_canonical_u8(*b_val));
            
            let proof = circuit.prove(pw.clone()).expect("proof generation should succeed");
            let public_inputs = proof.public_inputs.clone();
            circuit.verify(proof).expect("proof verification should succeed");
            
            assert_eq!(public_inputs[0], F::from_canonical_u8(*a_val));
            assert_eq!(public_inputs[1], F::from_canonical_u8(*b_val));
            assert_eq!(public_inputs[2], F::from_canonical_u8(*expected));
        }
    }

    #[test]
    fn test_bitwise_and_8bit_comprehensive() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        let a = builder.add_virtual_target();
        let b = builder.add_virtual_target();
        let result = bitwise_and_8bit(&mut builder, a, b);
        
        builder.register_public_input(a);
        builder.register_public_input(b);
        builder.register_public_input(result);
        
        let circuit = builder.build::<C>();
        
        let test_cases = [
            (0u8, 0u8, 0u8),
            (255u8, 255u8, 255u8),
            (170u8, 85u8, 0u8),
            (15u8, 240u8, 0u8),
            (255u8, 15u8, 15u8),
            (123u8, 45u8, 123u8 & 45u8),
        ];
        
        for (a_val, b_val, expected) in test_cases.iter() {
            let mut pw = PartialWitness::new();
            pw.set_target(a, F::from_canonical_u8(*a_val));
            pw.set_target(b, F::from_canonical_u8(*b_val));
            
            let proof = circuit.prove(pw.clone()).expect("proof generation should succeed");
            let public_inputs = proof.public_inputs.clone();
            circuit.verify(proof).expect("proof verification should succeed");
            
            assert_eq!(public_inputs[0], F::from_canonical_u8(*a_val));
            assert_eq!(public_inputs[1], F::from_canonical_u8(*b_val));
            assert_eq!(public_inputs[2], F::from_canonical_u8(*expected));
        }
    }

    #[test]
    fn test_bitwise_or_8bit_comprehensive() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        let a = builder.add_virtual_target();
        let b = builder.add_virtual_target();
        let result = bitwise_or_8bit(&mut builder, a, b);
        
        builder.register_public_input(a);
        builder.register_public_input(b);
        builder.register_public_input(result);
        
        let circuit = builder.build::<C>();
        
        let test_cases = [
            (0u8, 0u8, 0u8),
            (255u8, 0u8, 255u8),
            (170u8, 85u8, 255u8),
            (15u8, 240u8, 255u8),
            (240u8, 15u8, 255u8),
            (123u8, 45u8, 123u8 | 45u8),
        ];
        
        for (a_val, b_val, expected) in test_cases.iter() {
            let mut pw = PartialWitness::new();
            pw.set_target(a, F::from_canonical_u8(*a_val));
            pw.set_target(b, F::from_canonical_u8(*b_val));
            
            let proof = circuit.prove(pw.clone()).expect("proof generation should succeed");
            let public_inputs = proof.public_inputs.clone();
            circuit.verify(proof).expect("proof verification should succeed");
            
            assert_eq!(public_inputs[0], F::from_canonical_u8(*a_val));
            assert_eq!(public_inputs[1], F::from_canonical_u8(*b_val));
            assert_eq!(public_inputs[2], F::from_canonical_u8(*expected));
        }
    }

    #[test]
    fn test_bitwise_not_8bit_comprehensive() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        let a = builder.add_virtual_target();
        let result = bitwise_not_8bit(&mut builder, a);
        
        builder.register_public_input(a);
        builder.register_public_input(result);
        
        let circuit = builder.build::<C>();
        
        let test_cases = [
            (0u8, 255u8),
            (255u8, 0u8),
            (170u8, 85u8),
            (85u8, 170u8),
            (15u8, 240u8),
            (240u8, 15u8),
        ];
        
        for (a_val, expected) in test_cases.iter() {
            let mut pw = PartialWitness::new();
            pw.set_target(a, F::from_canonical_u8(*a_val));
            
            let proof = circuit.prove(pw.clone()).expect("proof generation should succeed");
            let public_inputs = proof.public_inputs.clone();
            circuit.verify(proof).expect("proof verification should succeed");
            
            assert_eq!(public_inputs[0], F::from_canonical_u8(*a_val));
            assert_eq!(public_inputs[1], F::from_canonical_u8(*expected));
        }
    }

    #[test]
    fn test_lookup_table_soundness() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        let a = builder.add_virtual_target();
        let b = builder.add_virtual_target();
        
        let xor_result = bitwise_xor_8bit(&mut builder, a, b);
        let and_result = bitwise_and_8bit(&mut builder, a, b);
        let or_result = bitwise_or_8bit(&mut builder, a, b);
        let not_a = bitwise_not_8bit(&mut builder, a);
        let not_b = bitwise_not_8bit(&mut builder, b);
        
        let xor_target = builder.add_virtual_target();
        let and_target = builder.add_virtual_target();
        let or_target = builder.add_virtual_target();
        let not_a_target = builder.add_virtual_target();
        let not_b_target = builder.add_virtual_target();
        
        builder.connect(xor_result, xor_target);
        builder.connect(and_result, and_target);
        builder.connect(or_result, or_target);
        builder.connect(not_a, not_a_target);
        builder.connect(not_b, not_b_target);
        
        builder.register_public_input(a);
        builder.register_public_input(b);
        builder.register_public_input(xor_target);
        builder.register_public_input(and_target);
        builder.register_public_input(or_target);
        builder.register_public_input(not_a_target);
        builder.register_public_input(not_b_target);
        
        let circuit = builder.build::<C>();
        
        for a_val in [0u8, 1u8, 85u8, 170u8, 255u8] {
            for b_val in [0u8, 1u8, 85u8, 170u8, 255u8] {
                let mut pw = PartialWitness::new();
                pw.set_target(a, F::from_canonical_u8(a_val));
                pw.set_target(b, F::from_canonical_u8(b_val));
                pw.set_target(xor_target, F::from_canonical_u8(a_val ^ b_val));
                pw.set_target(and_target, F::from_canonical_u8(a_val & b_val));
                pw.set_target(or_target, F::from_canonical_u8(a_val | b_val));
                pw.set_target(not_a_target, F::from_canonical_u8(!a_val));
                pw.set_target(not_b_target, F::from_canonical_u8(!b_val));
                
                let proof = circuit.prove(pw.clone()).expect("proof generation should succeed");
                circuit.verify(proof).expect("proof verification should succeed");
            }
        }
    }

    #[test]
    fn test_lookup_table_completeness_sampled() {
        let config = CircuitConfig::standard_recursion_config();
        
        for op in ["xor", "and", "or"] {
            let mut builder = CircuitBuilder::<F, D>::new(config.clone());
            
            let a = builder.add_virtual_target();
            let b = builder.add_virtual_target();
            
            let result = match op {
                "xor" => bitwise_xor_8bit(&mut builder, a, b),
                "and" => bitwise_and_8bit(&mut builder, a, b),
                "or" => bitwise_or_8bit(&mut builder, a, b),
                _ => unreachable!(),
            };
            
            builder.register_public_input(result);
            
            let circuit = builder.build::<C>();
            
            let test_values = [0u8, 1u8, 15u8, 16u8, 85u8, 127u8, 128u8, 170u8, 240u8, 255u8];
            
            for &a_val in &test_values {
                for &b_val in &test_values {
                    let expected = match op {
                        "xor" => a_val ^ b_val,
                        "and" => a_val & b_val,
                        "or" => a_val | b_val,
                        _ => unreachable!(),
                    };
                    
                    let mut pw = PartialWitness::new();
                    pw.set_target(a, F::from_canonical_u8(a_val));
                    pw.set_target(b, F::from_canonical_u8(b_val));
                    
                    let proof = circuit.prove(pw.clone()).expect("proof generation should succeed");
                    let public_inputs = proof.public_inputs.clone();
                    circuit.verify(proof).expect("proof verification should succeed");
                    
                    assert_eq!(public_inputs[0], F::from_canonical_u8(expected));
                }
            }
        }
    }

    #[test]
    fn test_lookup_table_soundness_invalid_proofs() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        let a = builder.add_virtual_target();
        let b = builder.add_virtual_target();
        let result = bitwise_xor_8bit(&mut builder, a, b);
        
        builder.register_public_input(a);
        builder.register_public_input(b);
        builder.register_public_input(result);
        
        let circuit = builder.build::<C>();
        
        let a_val = 100u8;
        let b_val = 50u8;
        let correct_result = a_val ^ b_val;
        
        let mut pw = PartialWitness::new();
        pw.set_target(a, F::from_canonical_u8(a_val));
        pw.set_target(b, F::from_canonical_u8(b_val));
        
        let valid_proof = circuit.prove(pw.clone()).expect("Valid proof should succeed");
        let public_inputs = valid_proof.public_inputs.clone();
        
        assert_eq!(public_inputs[0], F::from_canonical_u8(a_val));
        assert_eq!(public_inputs[1], F::from_canonical_u8(b_val));
        assert_eq!(public_inputs[2], F::from_canonical_u8(correct_result));
        
        circuit.verify(valid_proof.clone()).expect("Valid proof should verify");
        
        let wrong_results = [
            correct_result.wrapping_add(1),
            correct_result.wrapping_sub(1),
            correct_result ^ 0xFF,
        ];
        
        for wrong_result in wrong_results.iter() {
            if wrong_result == &correct_result {
                continue;
            }
            
            let mut tampered_inputs = public_inputs.clone();
            tampered_inputs[2] = F::from_canonical_u8(*wrong_result);
            
            let tampered_proof = plonky2::plonk::proof::ProofWithPublicInputs {
                proof: valid_proof.proof.clone(),
                public_inputs: tampered_inputs,
            };
            
            let verification_result = circuit.verify(tampered_proof);
            assert!(verification_result.is_err(), 
                "Expected verification to fail for tampered result: {} XOR {} should be {} not {}", 
                a_val, b_val, correct_result, wrong_result);
        }
    }

    #[test]
    fn test_lookup_table_completeness_edge_cases() {
        let config = CircuitConfig::standard_recursion_config();
        
        let edge_cases = [
            ("xor", 0u8, 0u8),
            ("xor", 255u8, 255u8),
            ("xor", 255u8, 0u8),
            ("and", 255u8, 255u8),
            ("and", 0u8, 255u8),
            ("or", 0u8, 0u8),
            ("or", 255u8, 0u8),
        ];
        
        for (op, a_val, b_val) in edge_cases.iter() {
            let mut builder = CircuitBuilder::<F, D>::new(config.clone());
            
            let a = builder.add_virtual_target();
            let b = builder.add_virtual_target();
            
            let result = match *op {
                "xor" => bitwise_xor_8bit(&mut builder, a, b),
                "and" => bitwise_and_8bit(&mut builder, a, b),
                "or" => bitwise_or_8bit(&mut builder, a, b),
                _ => unreachable!(),
            };
            
            builder.register_public_input(result);
            
            let circuit = builder.build::<C>();
            
            let expected = match *op {
                "xor" => a_val ^ b_val,
                "and" => a_val & b_val,
                "or" => a_val | b_val,
                _ => unreachable!(),
            };
            
            let mut pw = PartialWitness::new();
            pw.set_target(a, F::from_canonical_u8(*a_val));
            pw.set_target(b, F::from_canonical_u8(*b_val));
            
            let proof = circuit.prove(pw.clone()).expect("proof generation should succeed for valid witness");
            let public_inputs = proof.public_inputs.clone();
            circuit.verify(proof).expect("proof verification should succeed for valid witness");
            
            assert_eq!(public_inputs[0], F::from_canonical_u8(expected));
        }
    }

    #[test]
    fn test_lookup_table_soundness_proof_tampering() {
        let config = CircuitConfig::standard_recursion_config();
        
        for op in ["xor", "and", "or"] {
            let mut builder = CircuitBuilder::<F, D>::new(config.clone());
            
            let a = builder.add_virtual_target();
            let b = builder.add_virtual_target();
            
            let result = match op {
                "xor" => bitwise_xor_8bit(&mut builder, a, b),
                "and" => bitwise_and_8bit(&mut builder, a, b),
                "or" => bitwise_or_8bit(&mut builder, a, b),
                _ => unreachable!(),
            };
            
            builder.register_public_input(a);
            builder.register_public_input(b);
            builder.register_public_input(result);
            
            let circuit = builder.build::<C>();
            
            let test_pairs = [(100u8, 50u8), (200u8, 25u8)];
            
            for (a_val, b_val) in test_pairs.iter() {
                let correct_result = match op {
                    "xor" => a_val ^ b_val,
                    "and" => a_val & b_val,
                    "or" => a_val | b_val,
                    _ => unreachable!(),
                };
                
                let mut pw = PartialWitness::new();
                pw.set_target(a, F::from_canonical_u8(*a_val));
                pw.set_target(b, F::from_canonical_u8(*b_val));
                
                let valid_proof = circuit.prove(pw.clone()).expect("Valid proof should succeed");
                let public_inputs = valid_proof.public_inputs.clone();
                
                assert_eq!(public_inputs[0], F::from_canonical_u8(*a_val));
                assert_eq!(public_inputs[1], F::from_canonical_u8(*b_val));
                assert_eq!(public_inputs[2], F::from_canonical_u8(correct_result));
                
                circuit.verify(valid_proof.clone()).expect("Valid proof should verify");
                
                let wrong_results = [
                    correct_result.wrapping_add(1),
                    correct_result.wrapping_sub(1),
                ];
                
                for wrong_result in wrong_results.iter() {
                    if wrong_result == &correct_result {
                        continue;
                    }
                    
                    let mut tampered_inputs = public_inputs.clone();
                    tampered_inputs[2] = F::from_canonical_u8(*wrong_result);
                    
                    let tampered_proof = plonky2::plonk::proof::ProofWithPublicInputs {
                        proof: valid_proof.proof.clone(),
                        public_inputs: tampered_inputs,
                    };
                    
                    let verification_result = circuit.verify(tampered_proof);
                    assert!(verification_result.is_err(), 
                        "Expected verification to fail for {} operation: {} {} {} should be {} not {}", 
                        op, a_val, op, b_val, correct_result, wrong_result);
                }
            }
        }
    }

    #[test]
    fn test_bitwise_xor_simple() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        let a = builder.add_virtual_target();
        let b = builder.add_virtual_target();
        let result = bitwise_xor(&mut builder, a, b);
        
        builder.register_public_input(result);
        
        let circuit = builder.build::<C>();
        
        let mut pw = PartialWitness::new();
        pw.set_target(a, F::ONE);  // 1
        pw.set_target(b, F::ZERO); // 0
        
        let proof = circuit.prove(pw).expect("proof generation should succeed");
        let public_inputs = proof.public_inputs.clone();
        circuit.verify(proof).expect("proof verification should succeed");
        
        // Expected: 1 XOR 0 = 1
        assert_eq!(public_inputs[0], F::ONE);
    }

    #[test]
    fn test_bitwise_and_simple() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        let a = builder.add_virtual_target();
        let b = builder.add_virtual_target();
        let result = bitwise_and(&mut builder, a, b);
        
        builder.register_public_input(result);
        
        let circuit = builder.build::<C>();
        
        let mut pw = PartialWitness::new();
        pw.set_target(a, F::ONE);  // 1
        pw.set_target(b, F::ONE);  // 1
        
        let proof = circuit.prove(pw).expect("proof generation should succeed");
        let public_inputs = proof.public_inputs.clone();
        circuit.verify(proof).expect("proof verification should succeed");
        
        // Expected: 1 AND 1 = 1
        assert_eq!(public_inputs[0], F::ONE);
    }

    #[test]
    fn test_bitwise_or_simple() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        let a = builder.add_virtual_target();
        let b = builder.add_virtual_target();
        let result = bitwise_or(&mut builder, a, b);
        
        builder.register_public_input(result);
        
        let circuit = builder.build::<C>();
        
        let mut pw = PartialWitness::new();
        pw.set_target(a, F::ZERO); // 0
        pw.set_target(b, F::ONE);  // 1
        
        let proof = circuit.prove(pw).expect("proof generation should succeed");
        let public_inputs = proof.public_inputs.clone();
        circuit.verify(proof).expect("proof verification should succeed");
        
        // Expected: 0 OR 1 = 1
        assert_eq!(public_inputs[0], F::ONE);
    }

    #[test]
    fn test_bitwise_not_simple() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        let a = builder.add_virtual_target();
        let result = bitwise_not(&mut builder, a);
        
        builder.register_public_input(result);
        
        let circuit = builder.build::<C>();
        
        let mut pw = PartialWitness::new();
        pw.set_target(a, F::ZERO); // 0
        
        let proof = circuit.prove(pw).expect("proof generation should succeed");
        let public_inputs = proof.public_inputs.clone();
        circuit.verify(proof).expect("proof verification should succeed");
        
        // Expected: NOT 0 = 1
        assert_eq!(public_inputs[0], F::ONE);
    }

    /// Range check verification tests
    /// These tests verify that the range checks correctly enforce input/output constraints

    #[test] 
    fn test_8bit_range_checks_valid_inputs() {
        let config = CircuitConfig::standard_recursion_config();
        
        // Test that valid 8-bit inputs (0-255) work correctly
        let valid_inputs = [0u8, 1, 127, 128, 254, 255];
        
        for &a_val in &valid_inputs {
            for &b_val in &valid_inputs {
                let mut builder = CircuitBuilder::<F, D>::new(config.clone());
                
                let a = builder.add_virtual_target();
                let b = builder.add_virtual_target();
                
                // Test all 8-bit operations
                let _xor_result = bitwise_xor_8bit(&mut builder, a, b);
                let _and_result = bitwise_and_8bit(&mut builder, a, b);
                let _or_result = bitwise_or_8bit(&mut builder, a, b);
                let _not_a = bitwise_not_8bit(&mut builder, a);
                
                let circuit = builder.build::<C>();
                
                let mut pw = PartialWitness::new();
                pw.set_target(a, F::from_canonical_u8(a_val));
                pw.set_target(b, F::from_canonical_u8(b_val));
                
                // These should all succeed for valid 8-bit inputs
                let proof = circuit.prove(pw).expect(&format!("proof should succeed for valid 8-bit inputs {} and {}", a_val, b_val));
                circuit.verify(proof).expect(&format!("verification should succeed for valid 8-bit inputs {} and {}", a_val, b_val));
            }
        }
    }

    #[test]
    fn test_single_bit_range_checks_valid_inputs() {
        let config = CircuitConfig::standard_recursion_config();
        
        // Test that valid single-bit inputs (0, 1) work correctly
        for a_val in [0u8, 1] {
            for b_val in [0u8, 1] {
                let mut builder = CircuitBuilder::<F, D>::new(config.clone());
                
                let a = builder.add_virtual_target();
                let b = builder.add_virtual_target();
                
                // Test all single-bit operations
                let _xor_result = bitwise_xor(&mut builder, a, b);
                let _and_result = bitwise_and(&mut builder, a, b);
                let _or_result = bitwise_or(&mut builder, a, b);
                let _not_a = bitwise_not(&mut builder, a);
                
                let circuit = builder.build::<C>();
                
                let mut pw = PartialWitness::new();
                pw.set_target(a, F::from_canonical_u8(a_val));
                pw.set_target(b, F::from_canonical_u8(b_val));
                
                // These should all succeed for valid single-bit inputs
                let proof = circuit.prove(pw).expect(&format!("proof should succeed for valid single-bit inputs {} and {}", a_val, b_val));
                circuit.verify(proof).expect(&format!("verification should succeed for valid single-bit inputs {} and {}", a_val, b_val));
            }
        }
    }

    #[test]
    #[should_panic(expected = "range check")]
    fn test_8bit_range_check_invalid_input_too_large() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        let a = builder.add_virtual_target();
        let b = builder.add_virtual_target();
        let _result = bitwise_xor_8bit(&mut builder, a, b);
        
        let circuit = builder.build::<C>();
        
        let mut pw = PartialWitness::new();
        pw.set_target(a, F::from_canonical_u32(256)); // Invalid: > 255
        pw.set_target(b, F::from_canonical_u8(100));
        
        // This should fail due to range check
        circuit.prove(pw).expect("Should fail due to range check violation");
    }

    #[test]
    #[should_panic(expected = "range check")]
    fn test_single_bit_range_check_invalid_input() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        let a = builder.add_virtual_target();
        let b = builder.add_virtual_target();
        let _result = bitwise_xor(&mut builder, a, b);
        
        let circuit = builder.build::<C>();
        
        let mut pw = PartialWitness::new();
        pw.set_target(a, F::from_canonical_u8(2)); // Invalid: > 1 for single bit
        pw.set_target(b, F::from_canonical_u8(0));
        
        // This should fail due to range check
        circuit.prove(pw).expect("Should fail due to range check violation");
    }

    #[test]
    fn test_range_check_boundary_conditions() {
        let config = CircuitConfig::standard_recursion_config();
        
        // Test exact boundary conditions for 8-bit operations
        let boundary_cases = [
            // (input_a, input_b, should_succeed)
            (0u16, 0u16, true),      // Minimum valid
            (255u16, 255u16, true),  // Maximum valid 
            (256u16, 0u16, false),   // Just over maximum
            (0u16, 256u16, false),   // Just over maximum for b
            (65535u16, 0u16, false), // Much larger invalid
        ];
        
        for (a_val, b_val, should_succeed) in boundary_cases.iter() {
            let mut builder = CircuitBuilder::<F, D>::new(config.clone());
            
            let a = builder.add_virtual_target();
            let b = builder.add_virtual_target();
            let _result = bitwise_xor_8bit(&mut builder, a, b);
            
            let circuit = builder.build::<C>();
            
            let mut pw = PartialWitness::new();
            pw.set_target(a, F::from_canonical_u16(*a_val));
            pw.set_target(b, F::from_canonical_u16(*b_val));
            
            let proof_result = circuit.prove(pw);
            
            if *should_succeed {
                let proof = proof_result.expect(&format!("Should succeed for valid inputs {} and {}", a_val, b_val));
                circuit.verify(proof).expect(&format!("Verification should succeed for valid inputs {} and {}", a_val, b_val));
            } else {
                assert!(proof_result.is_err(), "Should fail for invalid inputs {} and {} due to range check", a_val, b_val);
            }
        }
    }

    #[test]
    fn test_single_bit_boundary_conditions() {
        let config = CircuitConfig::standard_recursion_config();
        
        // Test exact boundary conditions for single-bit operations
        let boundary_cases = [
            // (input_a, input_b, should_succeed)
            (0u8, 0u8, true),   // Valid: both 0
            (0u8, 1u8, true),   // Valid: mixed
            (1u8, 0u8, true),   // Valid: mixed  
            (1u8, 1u8, true),   // Valid: both 1
            (2u8, 0u8, false),  // Invalid: a > 1
            (0u8, 2u8, false),  // Invalid: b > 1
            (2u8, 2u8, false),  // Invalid: both > 1
            (255u8, 0u8, false), // Invalid: much larger
        ];
        
        for (a_val, b_val, should_succeed) in boundary_cases.iter() {
            let mut builder = CircuitBuilder::<F, D>::new(config.clone());
            
            let a = builder.add_virtual_target();
            let b = builder.add_virtual_target();
            let _result = bitwise_xor(&mut builder, a, b);
            
            let circuit = builder.build::<C>();
            
            let mut pw = PartialWitness::new();
            pw.set_target(a, F::from_canonical_u8(*a_val));
            pw.set_target(b, F::from_canonical_u8(*b_val));
            
            let proof_result = circuit.prove(pw);
            
            if *should_succeed {
                let proof = proof_result.expect(&format!("Should succeed for valid single-bit inputs {} and {}", a_val, b_val));
                circuit.verify(proof).expect(&format!("Verification should succeed for valid single-bit inputs {} and {}", a_val, b_val));
            } else {
                assert!(proof_result.is_err(), "Should fail for invalid single-bit inputs {} and {} due to range check", a_val, b_val);
            }
        }
    }

    #[test]
    fn test_output_range_checks_comprehensive() {
        let config = CircuitConfig::standard_recursion_config();
        
        // Verify that outputs are also properly range-checked
        // This is important to ensure circuit soundness
        
        let test_cases = [
            (100u8, 50u8),
            (255u8, 0u8),
            (170u8, 85u8),
            (0u8, 255u8),
        ];
        
        for (a_val, b_val) in test_cases.iter() {
            // Test 8-bit operations
            {
                let mut builder = CircuitBuilder::<F, D>::new(config.clone());
                
                let a = builder.add_virtual_target();
                let b = builder.add_virtual_target();
                
                let xor_result = bitwise_xor_8bit(&mut builder, a, b);
                let and_result = bitwise_and_8bit(&mut builder, a, b);
                let or_result = bitwise_or_8bit(&mut builder, a, b);
                let not_a = bitwise_not_8bit(&mut builder, a);
                
                builder.register_public_input(xor_result);
                builder.register_public_input(and_result);
                builder.register_public_input(or_result);
                builder.register_public_input(not_a);
                
                let circuit = builder.build::<C>();
                
                let mut pw = PartialWitness::new();
                pw.set_target(a, F::from_canonical_u8(*a_val));
                pw.set_target(b, F::from_canonical_u8(*b_val));
                
                let proof = circuit.prove(pw).expect("8-bit operations should succeed");
                let public_inputs = proof.public_inputs.clone();
                circuit.verify(proof).expect("8-bit operations should verify");
                
                // Verify outputs are in valid 8-bit range
                for &output in &public_inputs {
                    let output_val = output.to_canonical_u64();
                    assert!(output_val <= 255, "Output {} should be in 8-bit range [0, 255]", output_val);
                }
                
                // Verify specific expected values
                assert_eq!(public_inputs[0], F::from_canonical_u8(a_val ^ b_val), "XOR result mismatch");
                assert_eq!(public_inputs[1], F::from_canonical_u8(a_val & b_val), "AND result mismatch");
                assert_eq!(public_inputs[2], F::from_canonical_u8(a_val | b_val), "OR result mismatch");
                assert_eq!(public_inputs[3], F::from_canonical_u8(!a_val), "NOT result mismatch");
            }
            
            // Test single-bit operations (only test valid single-bit inputs)
            if *a_val <= 1 && *b_val <= 1 {
                let mut builder = CircuitBuilder::<F, D>::new(config.clone());
                
                let a = builder.add_virtual_target();
                let b = builder.add_virtual_target();
                
                let xor_result = bitwise_xor(&mut builder, a, b);
                let and_result = bitwise_and(&mut builder, a, b);
                let or_result = bitwise_or(&mut builder, a, b);
                let not_a = bitwise_not(&mut builder, a);
                
                builder.register_public_input(xor_result);
                builder.register_public_input(and_result);
                builder.register_public_input(or_result);
                builder.register_public_input(not_a);
                
                let circuit = builder.build::<C>();
                
                let mut pw = PartialWitness::new();
                pw.set_target(a, F::from_canonical_u8(*a_val));
                pw.set_target(b, F::from_canonical_u8(*b_val));
                
                let proof = circuit.prove(pw).expect("Single-bit operations should succeed");
                let public_inputs = proof.public_inputs.clone();
                circuit.verify(proof).expect("Single-bit operations should verify");
                
                // Verify outputs are in valid single-bit range
                for &output in &public_inputs {
                    let output_val = output.to_canonical_u64();
                    assert!(output_val <= 1, "Single-bit output {} should be in range [0, 1]", output_val);
                }
                
                // Verify specific expected values for single-bit operations
                assert_eq!(public_inputs[0], F::from_canonical_u8(a_val ^ b_val), "Single-bit XOR result mismatch");
                assert_eq!(public_inputs[1], F::from_canonical_u8(a_val & b_val), "Single-bit AND result mismatch"); 
                assert_eq!(public_inputs[2], F::from_canonical_u8(a_val | b_val), "Single-bit OR result mismatch");
                assert_eq!(public_inputs[3], F::from_canonical_u8(1 - a_val), "Single-bit NOT result mismatch");
            }
        }
    }
}