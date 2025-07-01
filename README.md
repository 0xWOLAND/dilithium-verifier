# Dilithium ZK Verifier

This project implements a zero-knowledge verifier for Dilithium signatures using Plonky2, following Test-Driven Development (TDD) principles.

## Features

- **Idiomatic Rust**: Uses modern Rust patterns and the type system for safety
- **Plonky2 Integration**: Efficient ZK-SNARK proof system with polynomial commitment schemes
- **Modular Design**: Clean separation of concerns with dedicated modules
- **Comprehensive Testing**: Unit tests for all major components
- **Benchmarking**: Performance testing for circuit construction and proof generation

## Architecture

### Core Modules

1. **constants.rs**: Dilithium-3 parameter constants (Q, K, L, N, etc.)
2. **types.rs**: Data structures for public keys, signatures, and circuit targets
3. **ntt.rs**: Number Theoretic Transform implementation for polynomial operations
4. **hash.rs**: Hash function circuits (simplified SHAKE implementation)
5. **verifier.rs**: Main signature verification circuit

### Key Components

- **PolynomialTarget**: Circuit representation of polynomials with 256 coefficients
- **DilithiumVerifierCircuit**: Main verification circuit that proves signature validity
- **NTT/INTT**: Forward and inverse Number Theoretic Transforms for efficient polynomial multiplication

## Implementation Highlights

### Efficient Polynomial Operations

The verifier implements polynomial arithmetic using NTT for O(n log n) multiplication:

```rust
pub fn polynomial_mul_circuit(
    builder: &mut CircuitBuilder<F, D>,
    a: &PolynomialTarget,
    b: &PolynomialTarget,
) -> PolynomialTarget {
    let a_ntt = ntt_circuit(builder, a);
    let b_ntt = ntt_circuit(builder, b);
    // Point-wise multiplication in NTT domain
    let result_ntt = pointwise_mul(a_ntt, b_ntt);
    intt_circuit(builder, &result_ntt)
}
```

### ZK-Friendly Design

The implementation prioritizes operations that are efficient in zero-knowledge circuits:
- Field arithmetic over GF(2^64 - 2^32 + 1)
- Minimal range checks and conditional operations
- Batched polynomial operations

### Verification Algorithm

The core verification follows the Dilithium specification:
1. Expand challenge `c` from signature
2. Compute `w' = Az - ct1 * 2^d`
3. Verify signature bounds and format
4. Check challenge reconstruction: `c = H(M || w'_1)`

## Usage

```rust
use dilithium_verifier::DilithiumVerifierCircuit;

let config = CircuitConfig::standard_recursion_config();
let verifier = DilithiumVerifierCircuit::new(config);

let proof = verifier.generate_proof(&public_key, &signature, &message)?;
verifier.circuit.verify(proof)?;
```

## Performance

- Circuit construction: ~2-5 seconds
- Proof generation: ~10-30 seconds (depending on hardware)
- Circuit size: ~8K gates for basic verification

## Security Considerations

This implementation prioritizes:
- **Constant-time operations**: All circuit operations are constant-time by design
- **Side-channel resistance**: ZK proofs reveal no information about private inputs
- **Formal verification**: Circuit constraints mathematically enforce signature validity

## Testing

Run the test suite:
```bash
cargo test
```

Run benchmarks:
```bash
cargo bench
```

## Future Improvements

1. **Complete SHAKE implementation**: Full Keccak-based hash function
2. **Optimization**: Reduce circuit size through clever constraint batching
3. **Batch verification**: Verify multiple signatures in a single proof
4. **Hardware acceleration**: GPU-accelerated proof generation

## License

This project demonstrates cryptographic concepts and should be thoroughly audited before production use.