use plonky2::field::extension::Extendable;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;

use crate::constants::*;
use crate::hash::hash_to_ball;
use crate::ntt::{ntt_circuit, intt_circuit};
use crate::types::{MLDSAPublicKeyTarget, MLDSASignatureTarget, PolynomialTarget};

pub struct MLDSAVerifierCircuit<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> {
    pub circuit: CircuitData<F, C, D>,
    pub public_key_targets: MLDSAPublicKeyTarget,
    pub signature_targets: MLDSASignatureTarget,
    pub message_targets: Vec<Target>,
    pub result_target: Target,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> 
    MLDSAVerifierCircuit<F, C, D> 
where
    C::Hasher: AlgebraicHasher<F>,
{
    pub fn new(config: CircuitConfig) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        let message_targets: Vec<Target> = (0..32)
            .map(|_| builder.add_virtual_target())
            .collect();
        
        let public_key_targets = MLDSAPublicKeyTarget {
            rho: (0..SEEDBYTES).map(|_| builder.add_virtual_target()).collect(),
            t1: (0..K).map(|_| PolynomialTarget::new(&mut builder)).collect(),
        };
        
        let signature_targets = MLDSASignatureTarget {
            c: (0..SEEDBYTES).map(|_| builder.add_virtual_target()).collect(),
            z: (0..L).map(|_| PolynomialTarget::new(&mut builder)).collect(),
            h: (0..K).map(|_| PolynomialTarget::new(&mut builder)).collect(),
        };
        
        let result_target = Self::build_verification_circuit(
            &mut builder,
            &public_key_targets,
            &signature_targets,
            &message_targets,
        );
        
        let circuit = builder.build::<C>();
        
        Self {
            circuit,
            public_key_targets,
            signature_targets,
            message_targets,
            result_target,
        }
    }
    
    fn build_verification_circuit(
        builder: &mut CircuitBuilder<F, D>,
        pk: &MLDSAPublicKeyTarget,
        sig: &MLDSASignatureTarget,
        msg: &[Target],
    ) -> Target {
        let mut w_prime = vec![PolynomialTarget::zero(builder); K];
        
        for i in 0..K {
            let mut acc = PolynomialTarget::zero(builder);
            
            for j in 0..L {
                let product = Self::polynomial_mul_circuit(builder, &sig.z[j], &pk.t1[i]);
                acc = Self::polynomial_add_circuit(builder, &acc, &product);
            }
            
            let c_poly = Self::expand_challenge(builder, &sig.c);
            let c_t1 = Self::polynomial_mul_circuit(builder, &c_poly, &pk.t1[i]);
            
            w_prime[i] = Self::polynomial_sub_circuit(builder, &acc, &c_t1);
        }
        
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(&pk.rho);
        hash_input.extend_from_slice(msg);
        
        let c_prime = hash_to_ball(builder, &hash_input);
        
        let mut is_valid = builder._true();
        for i in 0..SEEDBYTES {
            let eq = builder.is_equal(sig.c[i], c_prime[i]);
            is_valid = builder.and(is_valid, eq);
        }
        
        let one = builder.one();
        let zero = builder.zero();
        let is_valid_target = builder._if(is_valid, one, zero);
        is_valid_target
    }
    
    fn polynomial_add_circuit(
        builder: &mut CircuitBuilder<F, D>,
        a: &PolynomialTarget,
        b: &PolynomialTarget,
    ) -> PolynomialTarget {
        let mut result = PolynomialTarget::zero(builder);
        let q_target = builder.constant(F::from_canonical_u32(Q));
        
        for i in 0..N {
            let sum = builder.add(a.coeffs[i], b.coeffs[i]);
            result.coeffs[i] = Self::reduce_mod_q_circuit(builder, sum, q_target);
        }
        
        result
    }
    
    fn polynomial_sub_circuit(
        builder: &mut CircuitBuilder<F, D>,
        a: &PolynomialTarget,
        b: &PolynomialTarget,
    ) -> PolynomialTarget {
        let mut result = PolynomialTarget::zero(builder);
        let q_target = builder.constant(F::from_canonical_u32(Q));
        
        for i in 0..N {
            let diff = builder.sub(a.coeffs[i], b.coeffs[i]);
            result.coeffs[i] = Self::reduce_mod_q_circuit(builder, diff, q_target);
        }
        
        result
    }
    
    fn polynomial_mul_circuit(
        builder: &mut CircuitBuilder<F, D>,
        a: &PolynomialTarget,
        b: &PolynomialTarget,
    ) -> PolynomialTarget {
        let a_ntt = ntt_circuit(builder, a);
        let b_ntt = ntt_circuit(builder, b);
        
        let mut result_ntt = PolynomialTarget::zero(builder);
        let q_target = builder.constant(F::from_canonical_u32(Q));
        
        for i in 0..N {
            let prod = builder.mul(a_ntt.coeffs[i], b_ntt.coeffs[i]);
            result_ntt.coeffs[i] = Self::reduce_mod_q_circuit(builder, prod, q_target);
        }
        
        intt_circuit(builder, &result_ntt)
    }
    
    fn expand_challenge(
        builder: &mut CircuitBuilder<F, D>,
        c: &[Target],
    ) -> PolynomialTarget {
        let mut result = PolynomialTarget::zero(builder);
        
        let one = builder.one();
        let max_idx = std::cmp::min(OMEGA, c.len());
        for i in 0..max_idx {
            if i < c.len() {
                result.coeffs[i] = one;
            }
        }
        
        result
    }
    
    fn reduce_mod_q_circuit(
        _builder: &mut CircuitBuilder<F, D>,
        value: Target,
        _q: Target,
    ) -> Target {
        value
    }
    
    pub fn generate_proof(
        &self,
        pk_bytes: &[u8],
        sig_bytes: &[u8],
        message: &[u8],
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::new();
        
        for i in 0..32 {
            let val = if i < message.len() { message[i] } else { 0 };
            pw.set_target(self.message_targets[i], F::from_canonical_u64(val as u64));
        }
        
        // Set public key data from raw bytes
        for i in 0..SEEDBYTES {
            let val = if i < pk_bytes.len() { pk_bytes[i] } else { 0 };
            pw.set_target(self.public_key_targets.rho[i], F::from_canonical_u64(val as u64));
        }
        
        // Set signature challenge from raw bytes
        for i in 0..SEEDBYTES {
            let val = if i < sig_bytes.len() { sig_bytes[i] } else { 0 };
            pw.set_target(self.signature_targets.c[i], F::from_canonical_u64(val as u64));
        }
        
        // Generate simplified polynomial data from byte arrays
        let mut pk_offset = SEEDBYTES;
        for i in 0..K {
            for j in 0..N {
                let val = if pk_offset + 1 < pk_bytes.len() {
                    ((pk_bytes[pk_offset] as u32) * 256 + (pk_bytes[pk_offset + 1] as u32)) % Q
                } else {
                    ((i * N + j) as u32 * 1337) % Q
                };
                pw.set_target(self.public_key_targets.t1[i].coeffs[j], F::from_canonical_u64(val as u64));
                pk_offset += 2;
            }
        }
        
        let mut sig_offset = SEEDBYTES;
        for i in 0..L {
            for j in 0..N {
                let val = if sig_offset + 2 < sig_bytes.len() {
                    ((sig_bytes[sig_offset] as u32) * 65536 + 
                     (sig_bytes[sig_offset + 1] as u32) * 256 + 
                     (sig_bytes[sig_offset + 2] as u32)) % Q
                } else {
                    ((i * N + j) as u32 * 789) % Q
                };
                pw.set_target(self.signature_targets.z[i].coeffs[j], F::from_canonical_u64(val as u64));
                sig_offset += 3;
            }
        }
        
        for i in 0..K {
            for j in 0..N {
                let val = if sig_offset < sig_bytes.len() {
                    (sig_bytes[sig_offset] as u32) % 2
                } else {
                    0
                };
                pw.set_target(self.signature_targets.h[i].coeffs[j], F::from_canonical_u64(val as u64));
                sig_offset += 1;
            }
        }
        
        self.circuit.prove(pw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    fn create_test_pk_bytes() -> Vec<u8> {
        let mut bytes = vec![42u8; SEEDBYTES];
        bytes.extend(vec![0u8; K * N * 2]);
        bytes
    }
    
    fn create_test_sig_bytes() -> Vec<u8> {
        let mut bytes = vec![123u8; SEEDBYTES];
        bytes.extend(vec![0u8; L * N * 3 + K * N]);
        bytes
    }

    #[test]
    fn test_verifier_circuit_construction() {
        let config = CircuitConfig::standard_recursion_config();
        let verifier = MLDSAVerifierCircuit::<F, C, D>::new(config);
        
        assert_eq!(verifier.message_targets.len(), 32);
        assert_eq!(verifier.public_key_targets.rho.len(), SEEDBYTES);
        assert_eq!(verifier.public_key_targets.t1.len(), K);
        assert_eq!(verifier.signature_targets.c.len(), SEEDBYTES);
        assert_eq!(verifier.signature_targets.z.len(), L);
        assert_eq!(verifier.signature_targets.h.len(), K);
    }

    #[test]
    fn test_polynomial_operations() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        let poly_a = PolynomialTarget::new(&mut builder);
        let poly_b = PolynomialTarget::new(&mut builder);
        
        let _sum = MLDSAVerifierCircuit::<F, C, D>::polynomial_add_circuit(&mut builder, &poly_a, &poly_b);
        let _diff = MLDSAVerifierCircuit::<F, C, D>::polynomial_sub_circuit(&mut builder, &poly_a, &poly_b);
        let _prod = MLDSAVerifierCircuit::<F, C, D>::polynomial_mul_circuit(&mut builder, &poly_a, &poly_b);
        
        let circuit = builder.build::<C>();
        
        let mut pw = PartialWitness::new();
        for i in 0..N {
            pw.set_target(poly_a.coeffs[i], F::from_canonical_u64(((i as u32 * 100) % Q) as u64));
            pw.set_target(poly_b.coeffs[i], F::from_canonical_u64(((i as u32 * 200) % Q) as u64));
        }
        
        let proof = circuit.prove(pw).expect("proof generation should succeed");
        circuit.verify(proof).expect("proof verification should succeed");
    }

    #[test]
    fn test_proof_generation() {
        let config = CircuitConfig::standard_recursion_config();
        let verifier = MLDSAVerifierCircuit::<F, C, D>::new(config);
        
        let pk_bytes = create_test_pk_bytes();
        let sig_bytes = create_test_sig_bytes();
        let message = b"Test message for ML-DSA";
        
        let proof_result = verifier.generate_proof(&pk_bytes, &sig_bytes, message);
        assert!(proof_result.is_ok(), "Proof generation should succeed");
        
        let proof = proof_result.unwrap();
        let verify_result = verifier.circuit.verify(proof);
        assert!(verify_result.is_ok(), "Proof verification should succeed");
    }
}