use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::constants::*;

#[derive(Clone, Debug)]
pub struct PolynomialTarget {
    pub coeffs: Vec<Target>,
}

impl PolynomialTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let coeffs = (0..N).map(|_| builder.add_virtual_target()).collect();
        Self { coeffs }
    }

    pub fn zero<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let zero = builder.zero();
        let coeffs = vec![zero; N];
        Self { coeffs }
    }
}

#[derive(Clone, Debug)]
pub struct MLDSAPublicKeyTarget {
    pub rho: Vec<Target>,
    pub t1: Vec<PolynomialTarget>,
}

#[derive(Clone, Debug)]
pub struct MLDSASignatureTarget {
    pub c: Vec<Target>,
    pub z: Vec<PolynomialTarget>,
    pub h: Vec<PolynomialTarget>,
}