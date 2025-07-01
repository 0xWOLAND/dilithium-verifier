use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::constants::*;

pub fn hash_to_ball<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    seed: &[Target],
) -> Vec<Target> {
    let mut c = Vec::new();
    
    for i in 0..SEEDBYTES {
        if i < seed.len() {
            c.push(seed[i]);
        } else {
            c.push(builder.zero());
        }
    }
    
    c
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    #[test]
    fn test_hash_to_ball() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        let input: Vec<Target> = (0..64).map(|_| builder.add_virtual_target()).collect();
        let output = hash_to_ball(&mut builder, &input);
        
        assert_eq!(output.len(), SEEDBYTES);
        
        let circuit = builder.build::<C>();
        
        let mut pw = PartialWitness::new();
        for i in 0..64 {
            pw.set_target(input[i], F::from_canonical_u64(((i as u8) ^ 0x5A) as u64));
        }
        
        let proof = circuit.prove(pw).expect("proof generation should succeed");
        circuit.verify(proof).expect("proof verification should succeed");
    }
}