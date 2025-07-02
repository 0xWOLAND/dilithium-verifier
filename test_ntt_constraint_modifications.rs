use plonky2::field::types::Field;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::iop::witness::WitnessWrite;
use plonky2_field::types::{PrimeField64, Field64};
use anyhow::Result;
use ntt::{PolynomialTarget, NttGadget};

type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<2>>::F;
const D: usize = 2;

/// Modified polynomial addition that does subtraction instead
fn wrong_add_poly<F: plonky2::hash::hash_types::RichField + plonky2::field::extension::Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: &PolynomialTarget,
    b: &PolynomialTarget,
) -> PolynomialTarget {
    let mut coeffs = Vec::with_capacity(ntt::N);
    
    for i in 0..ntt::N {
        // INTENTIONAL ERROR: Using subtraction instead of addition
        let diff = NttGadget::sub_mod_q(builder, a.coeffs[i], b.coeffs[i]);
        coeffs.push(diff);
    }
    
    PolynomialTarget::from_targets(coeffs)
}

/// Modified polynomial scaling with wrong scaling factor
fn wrong_scale<F: plonky2::hash::hash_types::RichField + plonky2::field::extension::Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    poly: &PolynomialTarget,
    _scale_factor: plonky2::iop::target::Target, // Ignore the provided factor
) -> PolynomialTarget {
    let mut coeffs = Vec::with_capacity(ntt::N);
    
    // INTENTIONAL ERROR: Always use wrong scaling factor (3 instead of provided factor)
    let wrong_factor = builder.constant(F::from_canonical_u32(3));
    
    for i in 0..ntt::N {
        let scaled = NttGadget::montgomery_mul(builder, wrong_factor, poly.coeffs[i]);
        coeffs.push(scaled);
    }
    
    PolynomialTarget::from_targets(coeffs)
}

/// Modified polynomial addition with additional incorrect constraint (sum must equal first input)
fn add_poly_with_extra_constraint<F: plonky2::hash::hash_types::RichField + plonky2::field::extension::Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: &PolynomialTarget,
    b: &PolynomialTarget,
) -> PolynomialTarget {
    let mut coeffs = Vec::with_capacity(ntt::N);
    
    for i in 0..ntt::N {
        let sum = NttGadget::add_mod_q(builder, a.coeffs[i], b.coeffs[i]);
        coeffs.push(sum);
        
        // INTENTIONAL ERROR: Add constraint that sum must equal first input
        // This will fail unless b[i] = 0 for all i
        if i < 4 { // Only add constraint for first few coefficients to avoid too many conflicts
            builder.connect(sum, a.coeffs[i]);
        }
    }
    
    PolynomialTarget::from_targets(coeffs)
}

/// Test original (correct) polynomial addition
fn test_original_polynomial_addition() -> Result<()> {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let poly1 = PolynomialTarget::new(&mut builder);
    let poly2 = PolynomialTarget::new(&mut builder);
    
    let sum_poly = NttGadget::add_poly(&mut builder, &poly1, &poly2);

    // Register first 4 coefficients for testing
    for i in 0..4 {
        builder.register_public_input(poly1.coeffs[i]);
        builder.register_public_input(poly2.coeffs[i]);
        builder.register_public_input(sum_poly.coeffs[i]);
    }

    let data = builder.build::<C>();

    // Create test inputs
    let mut poly1_coeffs = vec![0u32; ntt::N];
    let mut poly2_coeffs = vec![0u32; ntt::N];
    
    poly1_coeffs[0] = 10; poly1_coeffs[1] = 20; poly1_coeffs[2] = 30; poly1_coeffs[3] = 40;
    poly2_coeffs[0] = 1;  poly2_coeffs[1] = 2;  poly2_coeffs[2] = 3;  poly2_coeffs[3] = 4;

    let mut pw = plonky2::iop::witness::PartialWitness::new();
    for i in 0..ntt::N {
        pw.set_target(poly1.coeffs[i], F::from_canonical_u32(poly1_coeffs[i]));
        pw.set_target(poly2.coeffs[i], F::from_canonical_u32(poly2_coeffs[i]));
    }

    let proof = data.prove(pw)?;
    data.verify(proof.clone())?;

    println!("✅ Original Polynomial Addition Results:");
    for i in 0..4 {
        let a_val = proof.public_inputs[i * 3].to_canonical_u64();
        let b_val = proof.public_inputs[i * 3 + 1].to_canonical_u64();
        let sum_val = proof.public_inputs[i * 3 + 2].to_canonical_u64();
        let expected = poly1_coeffs[i] + poly2_coeffs[i];
        
        println!("  Coeff {}: {} + {} = {} (expected {})", i, a_val, b_val, sum_val, expected);
        assert_eq!(sum_val, expected as u64);
    }

    Ok(())
}

/// Test polynomial addition with wrong operation (subtraction)
fn test_wrong_polynomial_operation() -> Result<()> {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let poly1 = PolynomialTarget::new(&mut builder);
    let poly2 = PolynomialTarget::new(&mut builder);
    
    let wrong_result = wrong_add_poly(&mut builder, &poly1, &poly2);

    // Register first 4 coefficients for testing
    for i in 0..4 {
        builder.register_public_input(poly1.coeffs[i]);
        builder.register_public_input(poly2.coeffs[i]);
        builder.register_public_input(wrong_result.coeffs[i]);
    }

    let data = builder.build::<C>();

    // Use same test inputs as original
    let mut poly1_coeffs = vec![0u32; ntt::N];
    let mut poly2_coeffs = vec![0u32; ntt::N];
    
    poly1_coeffs[0] = 10; poly1_coeffs[1] = 20; poly1_coeffs[2] = 30; poly1_coeffs[3] = 40;
    poly2_coeffs[0] = 1;  poly2_coeffs[1] = 2;  poly2_coeffs[2] = 3;  poly2_coeffs[3] = 4;

    let mut pw = plonky2::iop::witness::PartialWitness::new();
    for i in 0..ntt::N {
        pw.set_target(poly1.coeffs[i], F::from_canonical_u32(poly1_coeffs[i]));
        pw.set_target(poly2.coeffs[i], F::from_canonical_u32(poly2_coeffs[i]));
    }

    let proof = data.prove(pw)?;
    data.verify(proof.clone())?;

    println!("❌ Wrong Operation (Subtraction instead of Addition) Results:");
    for i in 0..4 {
        let a_val = proof.public_inputs[i * 3].to_canonical_u64();
        let b_val = proof.public_inputs[i * 3 + 1].to_canonical_u64();
        let result_val = proof.public_inputs[i * 3 + 2].to_canonical_u64();
        let expected_sum = poly1_coeffs[i] + poly2_coeffs[i];
        let expected_diff = if poly1_coeffs[i] >= poly2_coeffs[i] {
            poly1_coeffs[i] - poly2_coeffs[i]
        } else {
            (poly1_coeffs[i] as u64 + F::ORDER - poly2_coeffs[i] as u64) as u32
        };
        
        println!("  Coeff {}: {} + {} = {} (expected sum {}, got diff {})", 
                 i, a_val, b_val, result_val, expected_sum, expected_diff);
        
        // Verify we got subtraction instead of addition
        assert_ne!(result_val, expected_sum as u64, "Should NOT get addition result");
    }

    Ok(())
}

/// Test polynomial scaling with wrong scaling factor
fn test_wrong_scaling_factor() -> Result<()> {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let poly = PolynomialTarget::new(&mut builder);
    let scale_factor = builder.constant(F::from_canonical_u32(2)); // Want to scale by 2
    
    let wrong_scaled = wrong_scale(&mut builder, &poly, scale_factor);

    // Register first 4 coefficients for testing
    for i in 0..4 {
        builder.register_public_input(poly.coeffs[i]);
        builder.register_public_input(wrong_scaled.coeffs[i]);
    }

    let data = builder.build::<C>();

    // Create test inputs
    let mut poly_coeffs = vec![0u32; ntt::N];
    poly_coeffs[0] = 5; poly_coeffs[1] = 10; poly_coeffs[2] = 15; poly_coeffs[3] = 20;

    let mut pw = plonky2::iop::witness::PartialWitness::new();
    for i in 0..ntt::N {
        pw.set_target(poly.coeffs[i], F::from_canonical_u32(poly_coeffs[i]));
    }

    let proof = data.prove(pw)?;
    data.verify(proof.clone())?;

    println!("❌ Wrong Scaling Factor (3 instead of 2) Results:");
    for i in 0..4 {
        let original = proof.public_inputs[i * 2].to_canonical_u64();
        let scaled = proof.public_inputs[i * 2 + 1].to_canonical_u64();
        let expected_scale_by_2 = (poly_coeffs[i] * 2) as u64;
        let expected_scale_by_3 = (poly_coeffs[i] * 3) as u64;
        
        println!("  Coeff {}: {} * 2 = {} (expected {}, got {})", 
                 i, original, scaled, expected_scale_by_2, expected_scale_by_3);
        
        // Verify we got scaling by 3 instead of 2
        assert_ne!(scaled, expected_scale_by_2, "Should NOT get correct scaling by 2");
        // Note: Due to Montgomery multiplication, exact comparison might be complex
    }

    Ok(())
}

/// Test polynomial addition with extra constraint
fn test_extra_constraint() -> Result<()> {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let poly1 = PolynomialTarget::new(&mut builder);
    let poly2 = PolynomialTarget::new(&mut builder);
    
    let constrained_sum = add_poly_with_extra_constraint(&mut builder, &poly1, &poly2);

    // Register first 4 coefficients for testing
    for i in 0..4 {
        builder.register_public_input(poly1.coeffs[i]);
        builder.register_public_input(poly2.coeffs[i]);
        builder.register_public_input(constrained_sum.coeffs[i]);
    }

    let data = builder.build::<C>();

    println!("Testing polynomial addition with extra constraint (sum = first input)...");
    
    // Test Case 1: This should fail because sum != first input when second input != 0
    let mut poly1_coeffs = vec![0u32; ntt::N];
    let mut poly2_coeffs = vec![0u32; ntt::N];
    
    poly1_coeffs[0] = 10; poly1_coeffs[1] = 20; poly1_coeffs[2] = 30; poly1_coeffs[3] = 40;
    poly2_coeffs[0] = 1;  poly2_coeffs[1] = 2;  poly2_coeffs[2] = 3;  poly2_coeffs[3] = 4;

    let mut pw1 = plonky2::iop::witness::PartialWitness::new();
    for i in 0..ntt::N {
        pw1.set_target(poly1.coeffs[i], F::from_canonical_u32(poly1_coeffs[i]));
        pw1.set_target(poly2.coeffs[i], F::from_canonical_u32(poly2_coeffs[i]));
    }

    match data.prove(pw1) {
        Ok(_) => println!("❌ UNEXPECTED: Extra constraint should have failed"),
        Err(e) => println!("✅ Extra constraint correctly failed: {}", e),
    }

    Ok(())
}

fn main() -> Result<()> {
    println!("=== NTT CONSTRAINT MODIFICATION TESTING ===\n");
    
    println!("1. Testing Original (Correct) Polynomial Addition:");
    test_original_polynomial_addition()?;
    println!();
    
    println!("2. Testing Wrong Operation (Subtraction instead of Addition):");
    test_wrong_polynomial_operation()?;
    println!();
    
    println!("3. Testing Wrong Scaling Factor:");
    test_wrong_scaling_factor()?;
    println!();
    
    println!("4. Testing Additional Incorrect Constraint:");
    test_extra_constraint()?;
    println!();
    
    println!("=== NTT TESTING COMPLETE ===");
    Ok(())
}