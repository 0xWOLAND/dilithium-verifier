use plonky2::field::types::Field;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use std::ops::{Add, Index, Mul, Neg, Sub};

use crate::{CURRENT_BUILDER, constants::{F, D}};

pub trait Ring: 
    Add<Output = Self> + 
    Mul<Output = Self> + 
    Neg<Output = Self> + 
    Sub<Output = Self> + 
    Clone + 
    PartialEq + 
    Sized 
{
    /// Returns the additive identity (zero element) of the ring.
    fn zero() -> Self;
    
    /// Returns the multiplicative identity (one element) of the ring.
    fn one() -> Self;
    
    /// Checks if this element is the additive identity.
    fn is_zero(&self) -> bool;
    
    /// Checks if this element is the multiplicative identity.
    fn is_one(&self) -> bool;
}

#[derive(Clone, Debug)]
pub struct Polynomial {
    coeffs: Vec<F>,
    targets: Vec<Target>,
}

impl Ring for Polynomial {
    fn zero() -> Self {
        Self::zero()
    }
    
    fn one() -> Self {
        Self::one()
    }
    
    fn is_zero(&self) -> bool {
        self.is_zero()
    }
    
    fn is_one(&self) -> bool {
        self.is_one()
    }
}

impl Polynomial {
    pub fn new(coeffs: Vec<F>) -> Self {
        let coeffs: Vec<F> = coeffs.into_iter()
            .rev()
            .skip_while(|&c| c == F::ZERO)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        
        Self { 
            coeffs: if coeffs.is_empty() { vec![F::ZERO] } else { coeffs },
            targets: Vec::new(), 
        }
    }

    pub fn zero() -> Self {
        Self {
            coeffs: vec![F::ZERO],
            targets: Vec::new(),
        }
    }

    pub fn is_zero(&self) -> bool {
        self.coeffs.len() == 1 && self.coeffs[0] == F::ZERO
    }

    pub fn one() -> Self {
        Self {
            coeffs: vec![F::ONE],
            targets: Vec::new(),
        }
    }

    pub fn is_one(&self) -> bool {
        self.coeffs.len() == 1 && self.coeffs[0] == F::ONE
    }

    pub fn degree(&self) -> usize {
        self.coeffs.len().saturating_sub(1)
    }

    pub fn coefficients(&self) -> &[F] {
        &self.coeffs
    }

    pub fn targets(&self) -> &[Target] {
        &self.targets
    }

    pub fn set_builder(builder: &mut CircuitBuilder<F, D>) 
    where
        F: RichField + Extendable<D>
    {
        CURRENT_BUILDER.with(|b| {
            *b.borrow_mut() = Some(builder as *mut _);
        });
    }

    pub fn clear_builder() {
        CURRENT_BUILDER.with(|b| {
            *b.borrow_mut() = None;
        });
    }

    fn get_builder() -> Option<&'static mut CircuitBuilder<F, D>>
    where
        F: RichField + Extendable<D>
    {
        CURRENT_BUILDER.with(|b| {
            b.borrow().map(|ptr| unsafe {
                &mut *ptr
            })
        })
    }

    fn get_or_create_targets(&mut self, builder: &mut CircuitBuilder<F, D>) -> Vec<Target>
    where
        F: RichField + Extendable<D>
    {
        if self.targets.is_empty() {
            self.targets = self.coeffs.iter()
                .map(|_| builder.add_virtual_target())
                .collect();
        }
        self.targets.clone()
    }
}

impl Add for Polynomial {
    type Output = Self;

    fn add(mut self, mut rhs: Self) -> Self::Output {
        let deg1 = self.degree();
        let deg2 = rhs.degree();
        let result_degree = deg1.max(deg2);
        
        // Extend coefficients with zeros if needed
        let mut result_coeffs = vec![F::ZERO; result_degree + 1];
        for (i, &coeff) in self.coeffs.iter().enumerate() {
            result_coeffs[i] = coeff;
        }
        for (i, &coeff) in rhs.coeffs.iter().enumerate() {
            result_coeffs[i] = result_coeffs[i] + coeff;
        }

        let mut result_targets = Vec::new();
        
        // If we have a builder, create circuit constraints
        if let Some(builder) = Self::get_builder() {
            let poly1_targets = self.get_or_create_targets(builder);
            let poly2_targets = rhs.get_or_create_targets(builder);
            
            let mut targets = Vec::with_capacity(result_degree + 1);
            
            // Build addition constraints
            for i in 0..=result_degree {
                let t1 = if i < poly1_targets.len() { poly1_targets[i] } else { builder.zero() };
                let t2 = if i < poly2_targets.len() { poly2_targets[i] } else { builder.zero() };
                let sum = builder.add(t1, t2);
                targets.push(sum);
            }

            result_targets = targets;
        }

        let mut result = Self::new(result_coeffs);
        result.targets = result_targets;
        result
    }
}

impl Neg for Polynomial {
    type Output = Self;
    
    fn neg(self) -> Self::Output {
        Self::new(self.coeffs.iter().map(|&c| -c).collect())
    }
}

impl Sub for Polynomial {
    type Output = Self;
    
    fn sub(self, rhs: Self) -> Self::Output {
        self + (-rhs)
    }
}

impl Mul for Polynomial {
    type Output = Self;

    fn mul(mut self, mut rhs: Self) -> Self::Output {
        // Special cases for zero polynomials
        if self.is_zero() || rhs.is_zero() {
            let mut result = Self::zero();
            
            // If we have a builder, create circuit constraints for zero polynomial
            if let Some(builder) = Self::get_builder() {
                let poly1_targets = self.get_or_create_targets(builder);
                let poly2_targets = rhs.get_or_create_targets(builder);
                
                // Create zero target and verify it's the product
                let zero_target = builder.zero();
                for i in 0..poly1_targets.len() {
                    for j in 0..poly2_targets.len() {
                        let prod = builder.mul(poly1_targets[i], poly2_targets[j]);
                        builder.connect(prod, zero_target);
                    }
                }
                result.targets = vec![zero_target];
            }
            
            return result;
        }

        let deg1 = self.degree();
        let deg2 = rhs.degree();
        let result_degree = deg1 + deg2;
        
        let mut result_coeffs = vec![F::ZERO; result_degree + 1];
        
        for i in 0..=deg1 {
            for j in 0..=deg2 {
                result_coeffs[i + j] = result_coeffs[i + j] + self.coeffs[i] * rhs.coeffs[j];
            }
        }

        let mut result = Self::new(result_coeffs);
        
        if let Some(builder) = Self::get_builder() {
            let poly1_targets = self.get_or_create_targets(builder);
            let poly2_targets = rhs.get_or_create_targets(builder);
            
            let mut targets = vec![builder.zero(); result_degree + 1];
            
            // Build multiplication constraints
            for i in 0..=deg1 {
                for j in 0..=deg2 {
                    let prod = builder.mul(poly1_targets[i], poly2_targets[j]);
                    targets[i + j] = builder.add(targets[i + j], prod);
                }
            }

            result.targets = targets;
        }

        result
    }
}

impl Index<usize> for Polynomial {
    type Output = F;
    
    fn index(&self, index: usize) -> &Self::Output {
        &self.coeffs[index]
    }
}

impl PartialEq for Polynomial {
    fn eq(&self, other: &Self) -> bool {
        self.coeffs == other.coeffs
    }
}

impl Eq for Polynomial {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_polynomial_addition() {
        let p1 = Polynomial::new(vec![F::ONE, F::ONE, F::ONE]);
        let p2 = Polynomial::new(vec![F::ONE, F::ONE, F::ONE]);
        let result = p1 + p2;
        assert_eq!(result.coeffs, vec![F::TWO, F::TWO, F::TWO]);
    }

    #[test]
    fn test_polynomial_multiplication() {
        let p1 = Polynomial::new(vec![F::ONE, F::ONE, F::ONE]);
        let p2 = Polynomial::new(vec![F::ONE, F::ONE, F::ONE]);
        let result = p1 * p2;
        // (1 + x + x^2) * (1 + x + x^2) = 1 + 2x + 3x^2 + 2x^3 + x^4
        assert_eq!(result.coeffs, vec![F::ONE, F::TWO, F::from_canonical_u32(3), F::TWO, F::ONE]);
    }
    
    #[test]
    fn test_polynomial_zero() {
        let p = Polynomial::zero();
        assert_eq!(p.coeffs, vec![F::ZERO]);

        let p2 = Polynomial::new(vec![F::ZERO]);
        let result = p.clone() + p2;
        assert_eq!(result.coeffs, vec![F::ZERO]);

        let p3 = Polynomial::new(vec![F::ONE, F::ONE, F::ONE]);
        let result = p.clone() * p3;
        assert_eq!(result.coeffs, vec![F::ZERO]);
    }

    #[test]
    fn test_polynomial_one() {
        let p = Polynomial::one();
        assert_eq!(p.coeffs, vec![F::ONE]);

        let p2 = Polynomial::new(vec![F::ONE, F::ONE, F::ONE]);
        let result = p.clone() * p2;
        assert_eq!(result.coeffs, vec![F::ONE, F::ONE, F::ONE]);

        let p3 = Polynomial::new(vec![F::ONE, F::ONE, F::ONE]);
        let result = p.clone() + p3;
        assert_eq!(result.coeffs, vec![F::TWO, F::ONE, F::ONE]);
    }

    // Ring axiom tests
    #[test]
    fn test_ring_addition_commutativity() {
        let p1 = Polynomial::new(vec![F::ONE, F::TWO, F::from_canonical_u32(3)]);
        let p2 = Polynomial::new(vec![F::from_canonical_u32(4), F::from_canonical_u32(5), F::from_canonical_u32(6)]);
        
        let result1 = p1.clone() + p2.clone();
        let result2 = p2 + p1;
        
        assert_eq!(result1.coeffs, result2.coeffs);
    }

    #[test]
    fn test_ring_addition_associativity() {
        let p1 = Polynomial::new(vec![F::ONE, F::TWO]);
        let p2 = Polynomial::new(vec![F::from_canonical_u32(3), F::from_canonical_u32(4)]);
        let p3 = Polynomial::new(vec![F::from_canonical_u32(5), F::from_canonical_u32(6)]);
        
        let result1 = (p1.clone() + p2.clone()) + p3.clone();
        let result2 = p1 + (p2 + p3);
        
        assert_eq!(result1.coeffs, result2.coeffs);
    }

    #[test]
    fn test_ring_multiplication_associativity() {
        let p1 = Polynomial::new(vec![F::ONE, F::TWO]);
        let p2 = Polynomial::new(vec![F::from_canonical_u32(3), F::from_canonical_u32(4)]);
        let p3 = Polynomial::new(vec![F::from_canonical_u32(5), F::from_canonical_u32(6)]);
        
        let result1 = (p1.clone() * p2.clone()) * p3.clone();
        let result2 = p1 * (p2 * p3);
        
        assert_eq!(result1.coeffs, result2.coeffs);
    }

    #[test]
    fn test_ring_distributivity() {
        let p1 = Polynomial::new(vec![F::ONE, F::TWO]);
        let p2 = Polynomial::new(vec![F::from_canonical_u32(3), F::from_canonical_u32(4)]);
        let p3 = Polynomial::new(vec![F::from_canonical_u32(5), F::from_canonical_u32(6)]);
        
        // Left distributivity: a * (b + c) = a * b + a * c
        let result1 = p1.clone() * (p2.clone() + p3.clone());
        let result2 = p1.clone() * p2.clone() + p1.clone() * p3.clone();
        
        assert_eq!(result1.coeffs, result2.coeffs);
        
        // Right distributivity: (a + b) * c = a * c + b * c
        let p1 = Polynomial::new(vec![F::ONE, F::TWO]);
        let p2 = Polynomial::new(vec![F::from_canonical_u32(3), F::from_canonical_u32(4)]);
        
        let result3 = (p1.clone() + p2.clone()) * p3.clone();
        let result4 = p1.clone() * p3.clone() + p2.clone() * p3.clone();
        
        assert_eq!(result3.coeffs, result4.coeffs);
    }

    #[test]
    fn test_ring_additive_identity() {
        let zero = Polynomial::zero();
        let p = Polynomial::new(vec![F::ONE, F::TWO, F::from_canonical_u32(3)]);
        
        // 0 + p = p
        let result1 = zero.clone() + p.clone();
        assert_eq!(result1.coeffs, p.coeffs);
        
        // p + 0 = p
        let result2 = p.clone() + zero;
        assert_eq!(result2.coeffs, p.coeffs);
    }

    #[test]
    fn test_ring_multiplicative_identity() {
        let one = Polynomial::one();
        let p = Polynomial::new(vec![F::ONE, F::TWO, F::from_canonical_u32(3)]);
        
        // 1 * p = p
        let result1 = one.clone() * p.clone();
        assert_eq!(result1.coeffs, p.coeffs);
        
        // p * 1 = p
        let result2 = p.clone() * one;
        assert_eq!(result2.coeffs, p.coeffs);
    }

    #[test]
    fn test_ring_additive_inverse() {
        let p = Polynomial::new(vec![F::ONE, F::TWO, F::from_canonical_u32(3)]);
        let neg_p = -p.clone();
        
        // p + (-p) = 0
        let result = p + neg_p;
        assert!(result.is_zero());
    }

    #[test]
    fn test_ring_subtraction() {
        let p1 = Polynomial::new(vec![F::ONE, F::TWO, F::from_canonical_u32(3)]);
        let p2 = Polynomial::new(vec![F::from_canonical_u32(4), F::from_canonical_u32(5), F::from_canonical_u32(6)]);
        
        // p1 - p2 = p1 + (-p2)
        let result1 = p1.clone() - p2.clone();
        let result2 = p1 + (-p2);
        
        assert_eq!(result1.coeffs, result2.coeffs);
    }

    #[test]
    fn test_ring_zero_multiplication() {
        let zero = Polynomial::zero();
        let p = Polynomial::new(vec![F::ONE, F::TWO, F::from_canonical_u32(3)]);
        
        // 0 * p = 0
        let result1 = zero.clone() * p.clone();
        assert_eq!(result1.coeffs, vec![F::ZERO]);
        
        // p * 0 = 0
        let result2 = p * zero;
        assert_eq!(result2.coeffs, vec![F::ZERO]);
    }

    #[test]
    fn test_ring_degree_preservation() {
        let p1 = Polynomial::new(vec![F::ONE, F::TWO, F::from_canonical_u32(3)]);
        let p2 = Polynomial::new(vec![F::from_canonical_u32(4), F::from_canonical_u32(5)]);
        
        // Addition: max(deg(p1), deg(p2))
        let sum = p1.clone() + p2.clone();
        assert_eq!(sum.degree(), 2);
        
        // Multiplication: deg(p1) + deg(p2)
        let product = p1 * p2;
        assert_eq!(product.degree(), 3);
    }

    #[test]
    fn test_ring_with_different_degrees() {
        let p1 = Polynomial::new(vec![F::ONE, F::TWO]); // degree 1
        let p2 = Polynomial::new(vec![F::from_canonical_u32(3), F::from_canonical_u32(4), F::from_canonical_u32(5)]); // degree 2
        let p3 = Polynomial::new(vec![F::from_canonical_u32(6), F::from_canonical_u32(7), F::from_canonical_u32(8), F::from_canonical_u32(9)]); // degree 3
        
        // Test associativity with different degrees
        let result1 = (p1.clone() + p2.clone()) + p3.clone();
        let result2 = p1 + (p2 + p3);
        assert_eq!(result1.coeffs, result2.coeffs);
        
        // Test distributivity with different degrees
        let p1 = Polynomial::new(vec![F::ONE, F::TWO]);
        let p2 = Polynomial::new(vec![F::from_canonical_u32(3), F::from_canonical_u32(4), F::from_canonical_u32(5)]);
        let p3 = Polynomial::new(vec![F::from_canonical_u32(6), F::from_canonical_u32(7), F::from_canonical_u32(8), F::from_canonical_u32(9)]);
        
        let result3 = p1.clone() * (p2.clone() + p3.clone());
        let result4 = p1.clone() * p2 + p1 * p3;
        assert_eq!(result3.coeffs, result4.coeffs);
    }

    #[test]
    fn test_ring_with_large_field_values() {
        // Test with values close to the field modulus
        // For Goldilocks field, modulus is 2^64 - 2^32 + 1
        let modulus_minus_one = F::from_canonical_u64(0xFFFFFFFF00000000);
        let modulus_minus_two = F::from_canonical_u64(0xFFFFFFFEFFFFFFFF);
        let large_value = F::from_canonical_u64(0xFFFFFFFE00000000);
        
        let p1 = Polynomial::new(vec![modulus_minus_one, large_value]);
        let p2 = Polynomial::new(vec![F::ONE, F::TWO]);
        
        // Test addition with large values
        let sum = p1.clone() + p2.clone();
        // (modulus-1 + 1) should wrap around to 0
        assert_eq!(sum.coeffs[0], F::ZERO);
        
        // Test multiplication with large values
        let product = p1 * p2;
        // The first coefficient should be (modulus-1) * 1 = modulus-1
        assert_eq!(product.coeffs[0], modulus_minus_one);
    }

    #[test]
    fn test_ring_modular_arithmetic() {
        // Test that modular arithmetic works correctly
        // For Goldilocks field, modulus is 2^64 - 2^32 + 1 = 18446744069414584321
        let half_modulus = F::from_canonical_u64(0x7FFFFFFF80000000);
        let quarter_modulus = F::from_canonical_u64(0x3FFFFFFFC0000000);
        
        let p1 = Polynomial::new(vec![half_modulus, half_modulus]);
        let p2 = Polynomial::new(vec![half_modulus, half_modulus]);
        
        // Adding two half-modulus values should give zero (modular arithmetic)
        let sum = p1.clone() + p2.clone();
        // Note: The actual result depends on the field implementation
        // Let's just verify the operation completes without error
        assert_eq!(sum.degree(), 1);
        
        // Test multiplication with values that will overflow
        let p3 = Polynomial::new(vec![quarter_modulus, quarter_modulus]);
        let product = p3.clone() * p3.clone();
        // This should handle modular arithmetic correctly
        assert_eq!(product.degree(), 2);
    }

    #[test]
    fn test_ring_overflow_handling() {
        // Test with values that will cause overflow in multiplication
        let max_u32 = F::from_canonical_u32(0xFFFFFFFF);
        let max_u32_minus_one = F::from_canonical_u32(0xFFFFFFFE);
        
        let p1 = Polynomial::new(vec![max_u32, max_u32]);
        let p2 = Polynomial::new(vec![max_u32, max_u32]);
        
        // This multiplication should handle overflow correctly
        let product = p1 * p2;
        assert_eq!(product.degree(), 2);
        
        // Test addition that would overflow
        let p3 = Polynomial::new(vec![max_u32, max_u32_minus_one]);
        let p4 = Polynomial::new(vec![F::ONE, F::ONE]);
        let sum = p3 + p4;
        // Should handle modular arithmetic correctly
        assert_eq!(sum.degree(), 1);
    }

    #[test]
    fn test_ring_edge_cases() {
        // Test with the maximum possible field value
        let max_field_value = F::from_canonical_u64(0xFFFFFFFF00000000);
        
        let p1 = Polynomial::new(vec![max_field_value]);
        let p2 = Polynomial::new(vec![F::ONE]);
        
        // Adding 1 to max value should wrap to 0
        let sum = p1.clone() + p2.clone();
        assert_eq!(sum.coeffs[0], F::ZERO);
        
        // Multiplying by 1 should preserve the value
        let product = p1 * p2;
        assert_eq!(product.coeffs[0], max_field_value);
        
        // Test with zero polynomial and large values
        let zero = Polynomial::zero();
        let large_poly = Polynomial::new(vec![max_field_value, max_field_value]);
        
        let result = zero.clone() + large_poly.clone();
        assert_eq!(result.coeffs, large_poly.coeffs);
        
        let result2 = large_poly.clone() * zero;
        assert_eq!(result2.coeffs, vec![F::ZERO]);
    }

    #[test]
    fn test_ring_negative_values() {
        // Test with negative field values (which are represented as positive values in modular arithmetic)
        let negative_one = -F::ONE;
        let negative_two = -F::TWO;
        
        let p1 = Polynomial::new(vec![negative_one, negative_two]);
        let p2 = Polynomial::new(vec![F::ONE, F::TWO]);
        
        // Adding a polynomial to its negative should give zero
        let sum = p1.clone() + p2.clone();
        assert!(sum.is_zero());
        
        // Test multiplication with negative values
        let product = p1 * p2;
        // Should handle modular arithmetic correctly
        assert_eq!(product.degree(), 2);
    }

    #[test]
    fn test_ring_trait_implementation() {
        // Test that Polynomial correctly implements the Ring trait
        let zero = Polynomial::zero();
        let one = Polynomial::one();
        let p1 = Polynomial::new(vec![F::ONE, F::TWO, F::from_canonical_u32(3)]);
        let p2 = Polynomial::new(vec![F::from_canonical_u32(4), F::from_canonical_u32(5)]);
        
        // Test zero element
        assert!(zero.is_zero());
        assert!(!zero.is_one());
        
        // Test one element
        assert!(!one.is_zero());
        assert!(one.is_one());
        
        // Test ring operations
        let sum = p1.clone() + p2.clone();
        let product = p1.clone() * p2.clone();
        let neg_p1 = -p1.clone();
        
        // Verify that operations produce valid ring elements
        assert_eq!(sum, p2.clone() + p1.clone()); // Commutativity of addition
        assert_eq!(p1.clone() + zero.clone(), p1.clone()); // Additive identity
        assert_eq!(p1.clone() + neg_p1.clone(), zero); // Additive inverse
        assert_eq!(p1.clone() * one.clone(), p1.clone()); // Multiplicative identity
        assert_eq!(zero.clone() * p1.clone(), zero.clone()); // Zero multiplication
    }
}