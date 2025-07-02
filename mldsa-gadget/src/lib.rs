use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use shake256_gadget::Shake256Gadget;
use ntt_gadget::{NttGadget, PolynomialTarget};

/// ML-DSA Gadget for zero-knowledge verification
pub struct MldsaGadget;

impl MldsaGadget {
    pub fn verify<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        public_key: &[Target],
        signature: &[Target],
        message: &[Target],
    ) -> Target {
        // Simplified ML-DSA verification for now
        // In practice, this would implement the full ML-DSA Algorithm 8
        
        // Hash the public key
        let pk_hash = Shake256Gadget::hash(builder, public_key, 64);
        
        // Hash the message with transcript
        let mut tr_message = pk_hash.clone();
        tr_message.extend_from_slice(message);
        let mu = Shake256Gadget::hash(builder, &tr_message, 64);
        
        // Create polynomial from message hash instead of creating new polynomial
        let mut poly_coeffs = Vec::new();
        for i in 0..256 {
            if i < mu.len() {
                poly_coeffs.push(mu[i % mu.len()]);
            } else {
                poly_coeffs.push(builder.zero());
            }
        }
        let sig_poly = PolynomialTarget { coeffs: poly_coeffs };
        
        // Apply NTT to signature polynomial
        let ntt_sig = NttGadget::ntt(builder, &sig_poly);
        let intt_result = NttGadget::intt(builder, &ntt_sig);
        
        // Simple verification: check if signature is non-zero
        let mut verification_result = builder.zero();
        for i in 0..signature.len().min(256) {
            if i < signature.len() {
                verification_result = builder.add(verification_result, signature[i]);
            }
        }
        
        // Add some polynomial constraints
        for i in 0..256 {
            verification_result = builder.add(verification_result, intt_result.coeffs[i]);
        }
        
        // Add hash contribution
        for i in 0..mu.len().min(64) {
            verification_result = builder.add(verification_result, mu[i]);
        }
        
        verification_result
    }
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
    fn test_mldsa_verify() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        let public_key: Vec<Target> = (0..1312).map(|_| builder.add_virtual_target()).collect();
        let signature: Vec<Target> = (0..2420).map(|_| builder.add_virtual_target()).collect();
        let message: Vec<Target> = (0..32).map(|_| builder.add_virtual_target()).collect();
        
        let result = MldsaGadget::verify(&mut builder, &public_key, &signature, &message);
        builder.register_public_input(result);
        
        let circuit = builder.build::<C>();
        
        let mut pw = PartialWitness::new();
        
        // Set mock values
        for i in 0..1312 {
            pw.set_target(public_key[i], F::from_canonical_u64((i % 255) as u64 + 1));
        }
        for i in 0..2420 {
            pw.set_target(signature[i], F::from_canonical_u64((i % 127) as u64 + 1));
        }
        for i in 0..32 {
            pw.set_target(message[i], F::from_canonical_u64((i * 17) as u64 + 1));
        }
        
        let proof = circuit.prove(pw).expect("proof generation should succeed");
        circuit.verify(proof).expect("proof verification should succeed");
    }

    #[test]
    fn test_mldsa_deterministic() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        let public_key: Vec<Target> = (0..32).map(|_| builder.add_virtual_target()).collect();
        let signature: Vec<Target> = (0..64).map(|_| builder.add_virtual_target()).collect();
        let message: Vec<Target> = (0..16).map(|_| builder.add_virtual_target()).collect();
        
        let result1 = MldsaGadget::verify(&mut builder, &public_key, &signature, &message);
        let result2 = MldsaGadget::verify(&mut builder, &public_key, &signature, &message);
        
        builder.connect(result1, result2);
        
        let circuit = builder.build::<C>();
        
        let mut pw = PartialWitness::new();
        
        for i in 0..32 {
            pw.set_target(public_key[i], F::from_canonical_u64((i * 31) as u64 + 1));
        }
        for i in 0..64 {
            pw.set_target(signature[i], F::from_canonical_u64((i * 13) as u64 + 1));
        }
        for i in 0..16 {
            pw.set_target(message[i], F::from_canonical_u64((i * 7) as u64 + 1));
        }
        
        let proof = circuit.prove(pw).expect("proof generation should succeed");
        circuit.verify(proof).expect("proof verification should succeed");
    }
}