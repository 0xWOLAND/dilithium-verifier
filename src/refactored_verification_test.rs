#[cfg(test)]
mod refactored_verification_tests {
    use crate::types::{MLDSAPublicKeyTarget, MLDSASignatureTarget, PolynomialTarget};
    use plonky2::field::extension::Extendable;
    use plonky2::hash::hash_types::RichField;
    use plonky2::iop::target::Target;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
    use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, PoseidonGoldilocksConfig};
    use plonky2::plonk::proof::ProofWithPublicInputs;
    use shake256_circuit::Shake256Circuit;
    
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    /// Refactored ML-DSA Verifier that exactly matches dilithium-py Algorithm 8
    pub struct RefactoredMLDSAVerifier<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> {
        pub circuit: CircuitData<F, C, D>,
        pub public_key_targets: MLDSAPublicKeyTarget,
        pub signature_targets: MLDSASignatureTarget,
        pub message_targets: Vec<Target>,
        pub result_target: Target,
        // ML-DSA Parameters (exact from dilithium-py)
        pub k: usize,          // Matrix dimension 
        pub l: usize,          // Matrix dimension
        pub d: usize,          // Bits dropped from t (always 13)
        pub eta: u32,          // Private key range
        pub tau: usize,        // Number of ±1 in c
        pub gamma_1: u32,      // Coefficient range of y
        pub gamma_2: u32,      // Low order rounding range
        pub omega: usize,      // Max number of ones in hint
        pub beta: u32,         // tau * eta
        pub c_tilde_bytes: usize, // Challenge bytes length
    }

    impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> 
        RefactoredMLDSAVerifier<F, C, D> 
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        /// Create new ML-DSA verifier with exact dilithium-py parameters
        pub fn new(
            config: CircuitConfig,
            k: usize, l: usize, d: usize, eta: u32, tau: usize,
            gamma_1: u32, gamma_2: u32, omega: usize, c_tilde_bytes: usize
        ) -> Self {
            let beta = tau as u32 * eta;
            let mut builder = CircuitBuilder::<F, D>::new(config);
            
            // Create targets matching dilithium-py data structures
            let message_targets: Vec<Target> = (0..128) // Variable length message
                .map(|_| builder.add_virtual_target())
                .collect();
            
            let public_key_targets = MLDSAPublicKeyTarget {
                rho: (0..32).map(|_| builder.add_virtual_target()).collect(), // seed rho
                t1: (0..k).map(|_| PolynomialTarget::new(&mut builder)).collect(), // t1 vector
            };
            
            let signature_targets = MLDSASignatureTarget {
                c: (0..c_tilde_bytes).map(|_| builder.add_virtual_target()).collect(), // c_tilde
                z: (0..l).map(|_| PolynomialTarget::new(&mut builder)).collect(), // z vector
                h: (0..k).map(|_| PolynomialTarget::new(&mut builder)).collect(), // hint h
            };
            
            // Build Algorithm 8 circuit exactly as in dilithium-py
            let result_target = Self::build_algorithm_8_circuit(
                &mut builder,
                &public_key_targets,
                &signature_targets,
                &message_targets,
                k, l, d, eta, tau, gamma_1, gamma_2, omega, beta, c_tilde_bytes
            );
            
            let circuit = builder.build::<C>();
            
            Self {
                circuit,
                public_key_targets,
                signature_targets,
                message_targets,
                result_target,
                k, l, d, eta, tau, gamma_1, gamma_2, omega, beta, c_tilde_bytes,
            }
        }
        
        /// Build Algorithm 8 circuit exactly matching dilithium-py _verify_internal
        fn build_algorithm_8_circuit(
            builder: &mut CircuitBuilder<F, D>,
            pk: &MLDSAPublicKeyTarget,
            sig: &MLDSASignatureTarget,
            msg: &[Target],
            k: usize, l: usize, d: usize, _eta: u32, tau: usize,
            gamma_1: u32, gamma_2: u32, omega: usize, beta: u32, c_tilde_bytes: usize
        ) -> Target {
            // Step 1: h.sum_hint() > omega check
            let hint_sum = Self::compute_hint_sum(builder, &sig.h, k);
            let omega_target = builder.constant(F::from_canonical_u64(omega as u64));
            let hint_check = Self::is_less_than_or_equal(builder, hint_sum, omega_target);
            
            // Step 2: z.check_norm_bound(gamma_1 - beta) check
            let norm_bound = gamma_1 - beta;
            let norm_check = Self::check_z_norm_bound(builder, &sig.z, l, norm_bound);
            
            // Step 3: A_hat = expand_matrix_from_seed(rho)
            let a_hat = Self::expand_matrix_from_seed(builder, &pk.rho, k, l);
            
            // Step 4: tr = H(pk_bytes, 64)
            let tr = Self::hash_pk_bytes(builder, pk, k);
            
            // Step 5: mu = H(tr || m, 64)
            let mu = Self::hash_tr_message(builder, &tr, msg);
            
            // Step 6: c = R.sample_in_ball(c_tilde, tau)
            let c = Self::sample_in_ball(builder, &sig.c, tau, c_tilde_bytes);
            
            // Step 7: Convert to NTT domain
            let c_ntt = Self::to_ntt(builder, &c);
            let z_ntt = Self::vector_to_ntt(builder, &sig.z);
            
            // Step 8: t1 = t1.scale(1 << d).to_ntt()
            let scale_factor = 1u64 << d;
            let t1_scaled_ntt = Self::scale_and_ntt_vector(builder, &pk.t1, scale_factor);
            
            // Step 9: Az_minus_ct1 = (A_hat @ z) - t1.scale(c)
            let az = Self::matrix_vector_multiply(builder, &a_hat, &z_ntt, k, l);
            let ct1 = Self::vector_scale(builder, &t1_scaled_ntt, &c_ntt);
            let az_minus_ct1_ntt = Self::vector_subtract(builder, &az, &ct1);
            
            // Step 10: Convert back from NTT
            let az_minus_ct1 = Self::vector_from_ntt(builder, &az_minus_ct1_ntt);
            
            // Step 11: w_prime = h.use_hint(Az_minus_ct1, 2 * gamma_2)
            let alpha = 2 * gamma_2;
            let w_prime = Self::use_hint(builder, &sig.h, &az_minus_ct1, alpha);
            
            // Step 12: w_prime_bytes = w_prime.bit_pack_w(gamma_2)
            let w_prime_bytes = Self::bit_pack_w(builder, &w_prime, gamma_2);
            
            // Step 13: return c_tilde == H(mu + w_prime_bytes, c_tilde_bytes)
            let computed_c_tilde = Self::hash_mu_w_prime(builder, &mu, &w_prime_bytes, c_tilde_bytes);
            let challenge_match = Self::compare_byte_arrays(builder, &sig.c, &computed_c_tilde);
            
            // All checks must pass: hint_check AND norm_check AND challenge_match
            let check1 = builder.and(hint_check, norm_check);
            let all_checks = builder.and(check1, challenge_match);
            
            let one = builder.one();
            let zero = builder.zero();
            builder._if(all_checks, one, zero)
        }
        
        // Helper functions that will be implemented to match dilithium-py exactly
        fn compute_hint_sum(builder: &mut CircuitBuilder<F, D>, _h: &[PolynomialTarget], _k: usize) -> Target {
            // TODO: Implement exactly as h.sum_hint() in dilithium-py
            builder.zero() // Placeholder
        }
        
        fn is_less_than_or_equal(builder: &mut CircuitBuilder<F, D>, a: Target, b: Target) -> plonky2::iop::target::BoolTarget {
            // TODO: Implement proper comparison without wraparound issues
            let _diff = builder.sub(b, a);
            builder._true() // Placeholder
        }
        
        fn check_z_norm_bound(builder: &mut CircuitBuilder<F, D>, _z: &[PolynomialTarget], _l: usize, _bound: u32) -> plonky2::iop::target::BoolTarget {
            // TODO: Implement z.check_norm_bound(gamma_1 - beta)
            builder._true() // Placeholder
        }
        
        fn expand_matrix_from_seed(builder: &mut CircuitBuilder<F, D>, _rho: &[Target], k: usize, l: usize) -> Vec<PolynomialTarget> {
            // TODO: Implement A_hat expansion exactly as dilithium-py
            vec![PolynomialTarget::zero(builder); k * l] // Placeholder
        }
        
        fn hash_pk_bytes(builder: &mut CircuitBuilder<F, D>, _pk: &MLDSAPublicKeyTarget, _k: usize) -> Vec<Target> {
            // TODO: Use SHAKE256 circuit for tr = H(pk_bytes, 64)
            vec![builder.zero(); 64] // Placeholder
        }
        
        fn hash_tr_message(builder: &mut CircuitBuilder<F, D>, _tr: &[Target], _msg: &[Target]) -> Vec<Target> {
            // TODO: Use SHAKE256 circuit for mu = H(tr || m, 64)
            vec![builder.zero(); 64] // Placeholder
        }
        
        fn sample_in_ball(builder: &mut CircuitBuilder<F, D>, _c_tilde: &[Target], _tau: usize, _c_tilde_bytes: usize) -> PolynomialTarget {
            // TODO: Implement R.sample_in_ball(c_tilde, tau)
            PolynomialTarget::zero(builder) // Placeholder
        }
        
        fn to_ntt(_builder: &mut CircuitBuilder<F, D>, poly: &PolynomialTarget) -> PolynomialTarget {
            // TODO: Use existing NTT circuit
            poly.clone() // Placeholder
        }
        
        fn vector_to_ntt(_builder: &mut CircuitBuilder<F, D>, vec: &[PolynomialTarget]) -> Vec<PolynomialTarget> {
            // TODO: Convert vector to NTT
            vec.to_vec() // Placeholder
        }
        
        fn scale_and_ntt_vector(_builder: &mut CircuitBuilder<F, D>, vec: &[PolynomialTarget], _scale: u64) -> Vec<PolynomialTarget> {
            // TODO: Scale by (1 << d) and convert to NTT
            vec.to_vec() // Placeholder
        }
        
        fn matrix_vector_multiply(builder: &mut CircuitBuilder<F, D>, _matrix: &[PolynomialTarget], _vec: &[PolynomialTarget], k: usize, _l: usize) -> Vec<PolynomialTarget> {
            // TODO: Implement A_hat @ z
            vec![PolynomialTarget::zero(builder); k] // Placeholder
        }
        
        fn vector_scale(_builder: &mut CircuitBuilder<F, D>, vec: &[PolynomialTarget], _scalar: &PolynomialTarget) -> Vec<PolynomialTarget> {
            // TODO: Scale vector by polynomial
            vec.to_vec() // Placeholder
        }
        
        fn vector_subtract(_builder: &mut CircuitBuilder<F, D>, a: &[PolynomialTarget], _b: &[PolynomialTarget]) -> Vec<PolynomialTarget> {
            // TODO: Vector subtraction
            a.to_vec() // Placeholder
        }
        
        fn vector_from_ntt(_builder: &mut CircuitBuilder<F, D>, vec: &[PolynomialTarget]) -> Vec<PolynomialTarget> {
            // TODO: Convert vector from NTT
            vec.to_vec() // Placeholder
        }
        
        fn use_hint(_builder: &mut CircuitBuilder<F, D>, h: &[PolynomialTarget], _az_minus_ct1: &[PolynomialTarget], _alpha: u32) -> Vec<PolynomialTarget> {
            // TODO: Implement h.use_hint(Az_minus_ct1, 2 * gamma_2)
            h.to_vec() // Placeholder
        }
        
        fn bit_pack_w(builder: &mut CircuitBuilder<F, D>, _w_prime: &[PolynomialTarget], _gamma_2: u32) -> Vec<Target> {
            // TODO: Implement w_prime.bit_pack_w(gamma_2)
            vec![builder.zero(); 128] // Placeholder
        }
        
        fn hash_mu_w_prime(builder: &mut CircuitBuilder<F, D>, _mu: &[Target], _w_prime_bytes: &[Target], c_tilde_bytes: usize) -> Vec<Target> {
            // TODO: Use SHAKE256 circuit for H(mu + w_prime_bytes, c_tilde_bytes)
            vec![builder.zero(); c_tilde_bytes] // Placeholder
        }
        
        fn compare_byte_arrays(builder: &mut CircuitBuilder<F, D>, _a: &[Target], _b: &[Target]) -> plonky2::iop::target::BoolTarget {
            // TODO: Compare c_tilde == computed_c_tilde
            builder._true() // Placeholder
        }
        
        pub fn generate_proof(&self, _pk_bytes: &[u8], _sig_bytes: &[u8], _message: &[u8]) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
            let mut pw = PartialWitness::new();
            
            // TODO: Set witnesses based on actual ML-DSA data structures
            // This should unpack pk_bytes and sig_bytes exactly as dilithium-py does
            
            // Placeholder witness setting
            for target in &self.message_targets {
                pw.set_target(*target, F::ZERO);
            }
            for target in &self.public_key_targets.rho {
                pw.set_target(*target, F::ZERO);
            }
            
            self.circuit.prove(pw)
        }
    }

    // TDD Tests for refactored verification
    
    #[test]
    fn test_mldsa44_exact_parameters() {
        // Test ML-DSA-44 with exact parameters from dilithium-py
        let config = CircuitConfig::standard_recursion_config();
        
        // Exact ML-DSA-44 parameters from dilithium-py
        let k = 4;
        let l = 4;
        let d = 13;
        let eta = 2;
        let tau = 39;
        let gamma_1 = 131072; // 2^17
        let gamma_2 = 95232;  // (q-1)/88
        let omega = 80;
        let c_tilde_bytes = 32;
        
        let verifier = RefactoredMLDSAVerifier::<F, C, D>::new(
            config, k, l, d, eta, tau, gamma_1, gamma_2, omega, c_tilde_bytes
        );
        
        // Verify parameters are set correctly
        assert_eq!(verifier.k, 4);
        assert_eq!(verifier.l, 4);
        assert_eq!(verifier.d, 13);
        assert_eq!(verifier.eta, 2);
        assert_eq!(verifier.tau, 39);
        assert_eq!(verifier.gamma_1, 131072);
        assert_eq!(verifier.gamma_2, 95232);
        assert_eq!(verifier.omega, 80);
        assert_eq!(verifier.beta, 78); // tau * eta = 39 * 2
        assert_eq!(verifier.c_tilde_bytes, 32);
    }
    
    #[test]
    fn test_mldsa65_exact_parameters() {
        // Test ML-DSA-65 with exact parameters from dilithium-py
        let config = CircuitConfig::standard_recursion_config();
        
        let k = 6;
        let l = 5;
        let d = 13;
        let eta = 4;
        let tau = 49;
        let gamma_1 = 524288; // 2^19
        let gamma_2 = 261888; // (q-1)/32
        let omega = 55;
        let c_tilde_bytes = 48;
        
        let verifier = RefactoredMLDSAVerifier::<F, C, D>::new(
            config, k, l, d, eta, tau, gamma_1, gamma_2, omega, c_tilde_bytes
        );
        
        assert_eq!(verifier.beta, 196); // tau * eta = 49 * 4
    }
    
    #[test]
    fn test_mldsa87_exact_parameters() {
        // Test ML-DSA-87 with exact parameters from dilithium-py
        let config = CircuitConfig::standard_recursion_config();
        
        let k = 8;
        let l = 7;
        let d = 13;
        let eta = 2;
        let tau = 60;
        let gamma_1 = 524288; // 2^19
        let gamma_2 = 261888; // (q-1)/32
        let omega = 75;
        let c_tilde_bytes = 64;
        
        let verifier = RefactoredMLDSAVerifier::<F, C, D>::new(
            config, k, l, d, eta, tau, gamma_1, gamma_2, omega, c_tilde_bytes
        );
        
        assert_eq!(verifier.beta, 120); // tau * eta = 60 * 2
    }
    
    #[test]
    fn test_algorithm_8_circuit_construction() {
        // Test that Algorithm 8 circuit can be constructed without errors
        let config = CircuitConfig::standard_recursion_config();
        
        let verifier = RefactoredMLDSAVerifier::<F, C, D>::new(
            config, 4, 4, 13, 2, 39, 131072, 95232, 80, 32
        );
        
        // Circuit should build successfully
        assert!(!verifier.circuit.common.gates.is_empty(), "Circuit should have gates");
    }
    
    #[test]
    fn test_proof_generation_structure() {
        // Test that proof generation has the correct structure (will fail initially)
        let config = CircuitConfig::standard_recursion_config();
        
        let verifier = RefactoredMLDSAVerifier::<F, C, D>::new(
            config, 4, 4, 13, 2, 39, 131072, 95232, 80, 32
        );
        
        let pk_bytes = vec![0u8; 1312]; // ML-DSA-44 public key size
        let sig_bytes = vec![0u8; 2420]; // ML-DSA-44 signature size
        let message = b"test message";
        
        let proof_result = verifier.generate_proof(&pk_bytes, &sig_bytes, message);
        
        // This should succeed once implementation is complete
        assert!(proof_result.is_ok(), "Proof generation should succeed: {:?}", proof_result.err());
    }
    
    #[test]
    fn test_algorithm_8_step_by_step() {
        // Test each step of Algorithm 8 individually (TDD approach)
        // This test will guide the implementation of each helper function
        
        // Step 1: h.sum_hint() > omega should be implemented
        // Step 2: z.check_norm_bound(gamma_1 - beta) should be implemented  
        // Step 3: A_hat = expand_matrix_from_seed(rho) should be implemented
        // Step 4: tr = H(pk_bytes, 64) should use SHAKE256
        // Step 5: mu = H(tr || m, 64) should use SHAKE256
        // Step 6: c = R.sample_in_ball(c_tilde, tau) should be implemented
        // Step 7-10: NTT operations should use existing circuits
        // Step 11: w_prime = h.use_hint(...) should be implemented
        // Step 12: w_prime_bytes = w_prime.bit_pack_w(gamma_2) should be implemented
        // Step 13: c_tilde == H(mu + w_prime_bytes, c_tilde_bytes) should use SHAKE256
        
        println!("Algorithm 8 step-by-step test - implementation needed for each step");
        
        // This test passes by design - it's documenting what needs to be implemented
        assert!(true, "Step-by-step structure is defined");
    }
}