use std::ops::{Add, Mul};
use plonky2::field::types::Field;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::{CURRENT_BUILDER, constants::{F, D}};

#[derive(Clone)]
pub struct Polynomial {
    coeffs: Vec<F>,
    targets: Option<Vec<Target>>,
}

impl Polynomial {
    pub fn new(coeffs: Vec<F>) -> Self {
        Self { 
            coeffs,
            targets: None,
        }
    }

    pub fn degree(&self) -> usize {
        self.coeffs.len().saturating_sub(1)
    }

    pub fn coefficients(&self) -> &[F] {
        &self.coeffs
    }

    pub fn targets(&self) -> Option<&[Target]> {
        self.targets.as_deref()
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
        if let Some(targets) = &self.targets {
            targets.clone()
        } else {
            let targets: Vec<_> = self.coeffs.iter().map(|&coeff| {
                let target = builder.constant(coeff);
                builder.register_public_input(target);
                target
            }).collect();
            self.targets = Some(targets.clone());
            targets
        }
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

        let mut result_targets = None;
        
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

            result_targets = Some(targets);
        }

        Self {
            coeffs: result_coeffs,
            targets: result_targets,
        }
    }
}

impl Mul for Polynomial {
    type Output = Self;

    fn mul(mut self, mut rhs: Self) -> Self::Output {
        let deg1 = self.degree();
        let deg2 = rhs.degree();
        let result_degree = deg1 + deg2;
        
        let mut result_coeffs = vec![F::ZERO; result_degree + 1];
        
        // Regular coefficient multiplication
        for i in 0..=deg1 {
            for j in 0..=deg2 {
                result_coeffs[i + j] = result_coeffs[i + j] + self.coeffs[i] * rhs.coeffs[j];
            }
        }

        let mut result_targets = None;
        
        // If we have a builder, create circuit constraints
        if let Some(builder) = Self::get_builder() {
            let poly1_targets = self.get_or_create_targets(builder);
            let poly2_targets = rhs.get_or_create_targets(builder);
            
            let mut targets = vec![builder.zero(); result_degree + 1];
            
            // Build multiplication constraints
            for i in 0..=deg1 {
                for j in 0..=deg2 {
                    let prod = builder.mul(poly1_targets[i], poly2_targets[j]);
                    println!("Adding mul gate for x^{} * x^{}", i, j);
                    targets[i + j] = builder.add(targets[i + j], prod);
                    println!("Adding add gate for x^{} * x^{}", i, j);
                }
            }

            result_targets = Some(targets);
        }

        Self {
            coeffs: result_coeffs,
            targets: result_targets,
        }
    }
}

