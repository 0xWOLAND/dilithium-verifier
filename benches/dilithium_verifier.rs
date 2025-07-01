use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dilithium_verifier::{DilithiumVerifierCircuit, constants::*, types::*};
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::PoseidonGoldilocksConfig;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as plonky2::plonk::config::GenericConfig<D>>::F;

fn benchmark_circuit_construction(c: &mut Criterion) {
    c.bench_function("circuit_construction", |b| {
        b.iter(|| {
            let config = CircuitConfig::standard_recursion_config();
            black_box(DilithiumVerifierCircuit::<F, C, D>::new(config))
        })
    });
}

fn benchmark_proof_generation(c: &mut Criterion) {
    let config = CircuitConfig::standard_recursion_config();
    let verifier = DilithiumVerifierCircuit::<F, C, D>::new(config);
    
    let test_pk = DilithiumPublicKey {
        rho: [1; SEEDBYTES],
        t1: vec![vec![1000; N]; K],
    };
    
    let test_sig = DilithiumSignature {
        c: [2; SEEDBYTES],
        z: vec![vec![500; N]; L],
        h: vec![vec![0; N]; K],
    };
    
    let test_message = b"Benchmark test message";
    
    c.bench_function("proof_generation", |b| {
        b.iter(|| {
            black_box(verifier.generate_proof(&test_pk, &test_sig, test_message))
        })
    });
}

criterion_group!(benches, benchmark_circuit_construction, benchmark_proof_generation);
criterion_main!(benches);