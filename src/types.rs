use serde::{Deserialize, Serialize};
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::constants::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DilithiumPublicKey {
    pub rho: [u8; SEEDBYTES],
    pub t1: Vec<Vec<u32>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DilithiumSignature {
    pub c: [u8; SEEDBYTES],
    pub z: Vec<Vec<u32>>,
    pub h: Vec<Vec<u32>>,
}

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
pub struct DilithiumPublicKeyTarget {
    pub rho: Vec<Target>,
    pub t1: Vec<PolynomialTarget>,
}

#[derive(Clone, Debug)]
pub struct DilithiumSignatureTarget {
    pub c: Vec<Target>,
    pub z: Vec<PolynomialTarget>,
    pub h: Vec<PolynomialTarget>,
}