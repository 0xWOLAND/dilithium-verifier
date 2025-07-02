use plonky2::field::types::Field;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::iop::witness::WitnessWrite;
use plonky2_field::types::PrimeField64;
use anyhow::Result;

type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<2>>::F;
const D: usize = 2;

// Include the original bit-operations for reference
mod bit_operations_original {
    include!("bit-operations/src/lib.rs");
}

/// Modified XOR with INCORRECT constraint: uses AND table instead of XOR table
fn bitwise_xor_8bit_wrong_table<F: plonky2::hash::hash_types::RichField + plonky2::field::extension::Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: plonky2::iop::target::Target,
    b: plonky2::iop::target::Target,
) -> plonky2::iop::target::Target {
    // INTENTIONAL ERROR: Using AND table for XOR operation
    let wrong_table = bit_operations_original::create_8bit_and_table();
    let table_index = builder.add_lookup_table_from_pairs(wrong_table);
    
    let a_256 = builder.constant(F::from_canonical_u16(256));
    let packed_input = builder.mul(a, a_256);
    let packed_input = builder.add(packed_input, b);
    
    let result = builder.add_lookup_from_index(packed_input, table_index);
    result
}

/// Modified XOR with INCORRECT constraint: wrong packing formula
fn bitwise_xor_8bit_wrong_packing<F: plonky2::hash::hash_types::RichField + plonky2::field::extension::Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: plonky2::iop::target::Target,
    b: plonky2::iop::target::Target,
) -> plonky2::iop::target::Target {
    let xor_table = bit_operations_original::create_8bit_xor_table();
    let table_index = builder.add_lookup_table_from_pairs(xor_table);
    
    // INTENTIONAL ERROR: Wrong packing formula (should be a*256 + b, using a*128 + b)
    let wrong_multiplier = builder.constant(F::from_canonical_u16(128));
    let packed_input = builder.mul(a, wrong_multiplier);
    let packed_input = builder.add(packed_input, b);
    
    let result = builder.add_lookup_from_index(packed_input, table_index);
    result
}

/// Modified XOR with ADDITIONAL INCORRECT constraint: result must equal input a
fn bitwise_xor_8bit_extra_constraint<F: plonky2::hash::hash_types::RichField + plonky2::field::extension::Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: plonky2::iop::target::Target,
    b: plonky2::iop::target::Target,
) -> plonky2::iop::target::Target {
    let xor_table = bit_operations_original::create_8bit_xor_table();
    let table_index = builder.add_lookup_table_from_pairs(xor_table);
    
    let a_256 = builder.constant(F::from_canonical_u16(256));
    let packed_input = builder.mul(a, a_256);
    let packed_input = builder.add(packed_input, b);
    
    let result = builder.add_lookup_from_index(packed_input, table_index);
    
    // INTENTIONAL ERROR: Add incorrect constraint that result must equal input a
    // This will fail for most inputs since a XOR b != a (except when b = 0)
    builder.connect(result, a);
    
    result
}

/// Test original (correct) XOR operation
fn test_original_xor_operation() -> Result<()> {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let a = builder.add_virtual_target();
    let b = builder.add_virtual_target();
    
    let result = bit_operations_original::bitwise_xor_8bit(&mut builder, a, b);
    
    builder.register_public_input(a);
    builder.register_public_input(b);
    builder.register_public_input(result);

    let data = builder.build::<C>();

    // Test with valid inputs: 5 XOR 3 = 6
    let mut pw = plonky2::iop::witness::PartialWitness::new();
    pw.set_target(a, F::from_canonical_u8(5));
    pw.set_target(b, F::from_canonical_u8(3));

    let proof = data.prove(pw)?;
    data.verify(proof.clone())?;

    let result_val = proof.public_inputs[2].to_canonical_u64();
    assert_eq!(result_val, 6); // 5 XOR 3 = 6
    
    println!("✅ Original XOR operation: 5 ⊕ 3 = {}", result_val);
    Ok(())
}

/// Test XOR with wrong lookup table (should give wrong results)
fn test_xor_wrong_table() -> Result<()> {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let a = builder.add_virtual_target();
    let b = builder.add_virtual_target();
    
    let result = bitwise_xor_8bit_wrong_table(&mut builder, a, b);
    
    builder.register_public_input(a);
    builder.register_public_input(b);
    builder.register_public_input(result);

    let data = builder.build::<C>();

    // Test with same inputs: 5 XOR 3 should be 6, but we're using AND table
    let mut pw = plonky2::iop::witness::PartialWitness::new();
    pw.set_target(a, F::from_canonical_u8(5));
    pw.set_target(b, F::from_canonical_u8(3));

    let proof = data.prove(pw)?;
    data.verify(proof.clone())?;

    let result_val = proof.public_inputs[2].to_canonical_u64();
    
    // Should get AND result (5 & 3 = 1) instead of XOR result (5 ^ 3 = 6)
    println!("❌ Wrong table XOR operation: 5 ⊕ 3 = {} (should be 6, got AND result {})", 
             result_val, 5 & 3);
    
    // This demonstrates the constraint modification produces wrong results
    assert_eq!(result_val, 1); // 5 AND 3 = 1, not 6
    assert_ne!(result_val, 6); // Verify it's NOT the correct XOR result
    
    Ok(())
}

/// Test XOR with wrong packing (should cause lookup failures)
fn test_xor_wrong_packing() -> Result<()> {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let a = builder.add_virtual_target();
    let b = builder.add_virtual_target();
    
    let result = bitwise_xor_8bit_wrong_packing(&mut builder, a, b);
    
    builder.register_public_input(a);
    builder.register_public_input(b);
    builder.register_public_input(result);

    let data = builder.build::<C>();

    // Test with inputs that should work with correct packing
    let mut pw = plonky2::iop::witness::PartialWitness::new();
    pw.set_target(a, F::from_canonical_u8(5));
    pw.set_target(b, F::from_canonical_u8(3));

    println!("Testing XOR with wrong packing formula...");
    
    match data.prove(pw) {
        Ok(proof) => {
            // If it succeeds, it will give wrong results due to wrong lookup
            data.verify(proof.clone())?;
            let result_val = proof.public_inputs[2].to_canonical_u64();
            println!("❌ Wrong packing succeeded but gave incorrect result: {}", result_val);
            // The result should be wrong because we're looking up wrong indices
            assert_ne!(result_val, 6); // Should NOT be the correct XOR result
        }
        Err(e) => {
            println!("✅ Wrong packing correctly failed during proving: {}", e);
            // This is expected - wrong packing should cause lookup failures
        }
    }
    
    Ok(())
}

/// Test XOR with additional incorrect constraint
fn test_xor_extra_constraint() -> Result<()> {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let a = builder.add_virtual_target();
    let b = builder.add_virtual_target();
    
    let result = bitwise_xor_8bit_extra_constraint(&mut builder, a, b);
    
    builder.register_public_input(a);
    builder.register_public_input(b);
    builder.register_public_input(result);

    let data = builder.build::<C>();

    println!("Testing XOR with extra constraint (result = a)...");
    
    // Test Case 1: This should fail because 5 XOR 3 = 6 ≠ 5
    let mut pw1 = plonky2::iop::witness::PartialWitness::new();
    pw1.set_target(a, F::from_canonical_u8(5));
    pw1.set_target(b, F::from_canonical_u8(3));

    match data.prove(pw1) {
        Ok(_) => println!("❌ UNEXPECTED: Extra constraint should have failed for 5 ⊕ 3"),
        Err(e) => println!("✅ Extra constraint correctly failed for 5 ⊕ 3: {}", e),
    }
    
    // Test Case 2: This should succeed because 7 XOR 0 = 7 = 7
    let mut pw2 = plonky2::iop::witness::PartialWitness::new();
    pw2.set_target(a, F::from_canonical_u8(7));
    pw2.set_target(b, F::from_canonical_u8(0));

    match data.prove(pw2) {
        Ok(proof) => {
            data.verify(proof.clone())?;
            println!("✅ Extra constraint correctly succeeded for 7 ⊕ 0 = 7");
        }
        Err(e) => println!("❌ UNEXPECTED: Extra constraint should succeed for 7 ⊕ 0: {}", e),
    }
    
    Ok(())
}

fn main() -> Result<()> {
    println!("=== BIT-OPERATIONS CONSTRAINT MODIFICATION TESTING ===\n");
    
    println!("1. Testing Original (Correct) XOR Operation:");
    test_original_xor_operation()?;
    println!();
    
    println!("2. Testing XOR with Wrong Lookup Table:");
    test_xor_wrong_table()?;
    println!();
    
    println!("3. Testing XOR with Wrong Packing Formula:");
    test_xor_wrong_packing()?;
    println!();
    
    println!("4. Testing XOR with Additional Incorrect Constraint:");
    test_xor_extra_constraint()?;
    println!();
    
    println!("=== BIT-OPERATIONS TESTING COMPLETE ===");
    Ok(())
}