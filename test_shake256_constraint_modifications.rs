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

/// Modified SHAKE256 with WRONG output length calculation
fn shake256_wrong_output_length<F: plonky2::hash::hash_types::RichField + plonky2::field::extension::Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    input: &[plonky2::iop::target::Target],
    requested_len: usize,
) -> Vec<plonky2::iop::target::Target> {
    // INTENTIONAL ERROR: Always return double the requested length
    let wrong_output_len = requested_len * 2;
    
    // Simple hash simulation (not real SHAKE256)
    let mut output = Vec::new();
    for i in 0..wrong_output_len {
        let base = if i < input.len() { input[i] } else { builder.zero() };
        let hash_const = builder.constant(F::from_canonical_u32((i + 1) as u32));
        let result = builder.add(base, hash_const);
        output.push(result);
    }
    
    output
}

/// Modified SHAKE256 with WRONG padding
fn shake256_wrong_padding<F: plonky2::hash::hash_types::RichField + plonky2::field::extension::Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    input: &[plonky2::iop::target::Target],
    output_len: usize,
) -> Vec<plonky2::iop::target::Target> {
    // INTENTIONAL ERROR: Use wrong padding (add 0xFF instead of proper SHAKE256 padding)
    let mut padded_input = input.to_vec();
    let wrong_padding = builder.constant(F::from_canonical_u8(0xFF));
    padded_input.push(wrong_padding);
    
    // Simple hash simulation
    let mut output = Vec::new();
    for i in 0..output_len {
        let base = if i < padded_input.len() { padded_input[i] } else { builder.zero() };
        let hash_const = builder.constant(F::from_canonical_u32((i * 3 + 7) as u32));
        let result = builder.add(base, hash_const);
        output.push(result);
    }
    
    output
}

/// Modified SHAKE256 with ADDITIONAL INCORRECT constraint (first output must equal first input)
fn shake256_output_equals_input<F: plonky2::hash::hash_types::RichField + plonky2::field::extension::Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    input: &[plonky2::iop::target::Target],
    output_len: usize,
) -> Vec<plonky2::iop::target::Target> {
    // Simple hash simulation
    let mut output = Vec::new();
    for i in 0..output_len {
        let base = if i < input.len() { input[i] } else { builder.zero() };
        let hash_const = builder.constant(F::from_canonical_u32((i * 5 + 11) as u32));
        let result = builder.add(base, hash_const);
        output.push(result);
    }
    
    // INTENTIONAL ERROR: Add constraint that first output must equal first input
    if !output.is_empty() && !input.is_empty() {
        builder.connect(output[0], input[0]);
    }
    
    output
}

/// Original (simplified) SHAKE256 implementation for comparison
fn shake256_simplified<F: plonky2::hash::hash_types::RichField + plonky2::field::extension::Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    input: &[plonky2::iop::target::Target],
    output_len: usize,
) -> Vec<plonky2::iop::target::Target> {
    // Simple but correct hash simulation
    let mut output = Vec::new();
    for i in 0..output_len {
        let base = if i < input.len() { input[i] } else { builder.zero() };
        let hash_const = builder.constant(F::from_canonical_u32((i + 1) as u32));
        let result = builder.add(base, hash_const);
        output.push(result);
    }
    
    output
}

/// Test original (simplified) SHAKE256
fn test_original_shake256() -> Result<()> {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Create test input
    let mut input_targets = Vec::new();
    for _ in 0..4 {
        input_targets.push(builder.add_virtual_target());
    }
    
    let output_len = 8;
    let hash_output = shake256_simplified(&mut builder, &input_targets, output_len);

    // Register inputs and outputs
    for i in 0..input_targets.len() {
        builder.register_public_input(input_targets[i]);
    }
    for i in 0..output_len {
        builder.register_public_input(hash_output[i]);
    }

    let data = builder.build::<C>();

    // Create test input values
    let input_values = [10u32, 20, 30, 40];
    let mut pw = plonky2::iop::witness::PartialWitness::new();
    for i in 0..input_targets.len() {
        pw.set_target(input_targets[i], F::from_canonical_u32(input_values[i]));
    }

    let proof = data.prove(pw)?;
    data.verify(proof.clone())?;

    println!("✅ Original (Simplified) SHAKE256 Results:");
    println!("  Input: {:?}", input_values);
    print!("  Output: [");
    for i in 0..output_len {
        let output_val = proof.public_inputs[input_targets.len() + i].to_canonical_u64();
        print!("{}", output_val);
        if i < output_len - 1 { print!(", "); }
        
        // Verify expected result
        let expected = input_values.get(i).unwrap_or(&0) + (i + 1) as u32;
        assert_eq!(output_val, expected as u64);
    }
    println!("]");

    Ok(())
}

/// Test SHAKE256 with wrong output length
fn test_shake256_wrong_output_length() -> Result<()> {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Create test input
    let mut input_targets = Vec::new();
    for _ in 0..4 {
        input_targets.push(builder.add_virtual_target());
    }
    
    let requested_len = 4;
    let hash_output = shake256_wrong_output_length(&mut builder, &input_targets, requested_len);

    // Register inputs and outputs (should be double the requested length)
    for i in 0..input_targets.len() {
        builder.register_public_input(input_targets[i]);
    }
    for i in 0..hash_output.len() {
        builder.register_public_input(hash_output[i]);
    }

    let data = builder.build::<C>();

    // Create test input values
    let input_values = [10u32, 20, 30, 40];
    let mut pw = plonky2::iop::witness::PartialWitness::new();
    for i in 0..input_targets.len() {
        pw.set_target(input_targets[i], F::from_canonical_u32(input_values[i]));
    }

    let proof = data.prove(pw)?;
    data.verify(proof.clone())?;

    println!("❌ Wrong Output Length (requested {}, got {}) SHAKE256 Results:", 
             requested_len, hash_output.len());
    println!("  Input: {:?}", input_values);
    print!("  Output: [");
    for i in 0..hash_output.len() {
        let output_val = proof.public_inputs[input_targets.len() + i].to_canonical_u64();
        print!("{}", output_val);
        if i < hash_output.len() - 1 { print!(", "); }
    }
    println!("]");
    
    // Verify we got wrong length
    assert_eq!(hash_output.len(), requested_len * 2, "Should get double the requested length");

    Ok(())
}

/// Test SHAKE256 with wrong padding
fn test_shake256_wrong_padding() -> Result<()> {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Create test input
    let mut input_targets = Vec::new();
    for _ in 0..4 {
        input_targets.push(builder.add_virtual_target());
    }
    
    let output_len = 6;
    let hash_output = shake256_wrong_padding(&mut builder, &input_targets, output_len);

    // Register inputs and outputs
    for i in 0..input_targets.len() {
        builder.register_public_input(input_targets[i]);
    }
    for i in 0..output_len {
        builder.register_public_input(hash_output[i]);
    }

    let data = builder.build::<C>();

    // Create test input values
    let input_values = [10u32, 20, 30, 40];
    let mut pw = plonky2::iop::witness::PartialWitness::new();
    for i in 0..input_targets.len() {
        pw.set_target(input_targets[i], F::from_canonical_u32(input_values[i]));
    }

    let proof = data.prove(pw)?;
    data.verify(proof.clone())?;

    println!("❌ Wrong Padding (0xFF instead of proper SHAKE256) Results:");
    println!("  Input: {:?}", input_values);
    print!("  Output: [");
    for i in 0..output_len {
        let output_val = proof.public_inputs[input_targets.len() + i].to_canonical_u64();
        print!("{}", output_val);
        if i < output_len - 1 { print!(", "); }
        
        // This should give different results than the original due to wrong padding
    }
    println!("]");

    Ok(())
}

/// Test SHAKE256 with incorrect constraint
fn test_shake256_incorrect_constraint() -> Result<()> {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Create test input
    let mut input_targets = Vec::new();
    for _ in 0..4 {
        input_targets.push(builder.add_virtual_target());
    }
    
    let output_len = 4;
    let hash_output = shake256_output_equals_input(&mut builder, &input_targets, output_len);

    // Register inputs and outputs
    for i in 0..input_targets.len() {
        builder.register_public_input(input_targets[i]);
    }
    for i in 0..output_len {
        builder.register_public_input(hash_output[i]);
    }

    let data = builder.build::<C>();

    println!("Testing SHAKE256 with incorrect constraint (output[0] = input[0])...");
    
    // Test Case 1: This should fail unless input[0] + hash_const == input[0] (impossible unless hash_const = 0)
    let input_values = [10u32, 20, 30, 40];
    let mut pw = plonky2::iop::witness::PartialWitness::new();
    for i in 0..input_targets.len() {
        pw.set_target(input_targets[i], F::from_canonical_u32(input_values[i]));
    }

    match data.prove(pw) {
        Ok(_) => {
            println!("❌ UNEXPECTED: Constraint should have failed because output[0] != input[0]");
        }
        Err(e) => {
            println!("✅ Constraint correctly failed: {}", e);
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    println!("=== SHAKE256 CONSTRAINT MODIFICATION TESTING ===\n");
    
    println!("1. Testing Original (Simplified) SHAKE256:");
    test_original_shake256()?;
    println!();
    
    println!("2. Testing Wrong Output Length:");
    test_shake256_wrong_output_length()?;
    println!();
    
    println!("3. Testing Wrong Padding:");
    test_shake256_wrong_padding()?;
    println!();
    
    println!("4. Testing Incorrect Constraint:");
    test_shake256_incorrect_constraint()?;
    println!();
    
    println!("=== SHAKE256 TESTING COMPLETE ===");
    Ok(())
}