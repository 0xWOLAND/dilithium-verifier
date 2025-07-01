# ML-DSA Verifier

A polymorphic Rust implementation of ML-DSA (Module Lattice Digital Signature Algorithm) supporting all three security variants through a unified trait interface.

## Overview

This project implements ML-DSA signature verification using the [pqcrypto](https://github.com/rustpq/pqcrypto) Rust bindings, which provide C-bindings to the standardized [PQClean](https://github.com/pqclean/pqclean/) C library. The implementation uses a polymorphic design with the `MLDSAVariant` trait to support all three ML-DSA variants.

Each variant (ML-DSA-44, ML-DSA-65, ML-DSA-87) uses its dedicated implementation from the pqcrypto-mldsa crate modules: `mldsa44`, `mldsa65`, and `mldsa87` respectively, ensuring authentic variant-specific behavior and different key/signature sizes.

## Features

- **Polymorphic Design**: Unified `MLDSAVariant` trait for all ML-DSA variants
- **Three Security Levels**: ML-DSA-44, ML-DSA-65, and ML-DSA-87
- ML-DSA signature generation and verification

## Variants

Each variant uses its specific implementation from the pqcrypto-mldsa crate:

| Variant | Security Level | Parameters (k, l) | Public Key Size | Signature Size |
|---------|----------------|-------------------|-----------------|----------------|
| ML-DSA-44 | 2 (128-bit) | (4, 4) | 1312 bytes | ~2420 bytes |
| ML-DSA-65 | 3 (192-bit) | (6, 5) | 1952 bytes | ~3309 bytes |
| ML-DSA-87 | 5 (256-bit) | (8, 7) | 2592 bytes | ~4627 bytes |

## Usage

```rust
use mldsa_verifier::{MLDSAVariant, MLDSA44, MLDSA65, MLDSA87};

// Test any variant using the trait
fn test_variant<V: MLDSAVariant>(variant: V, name: &str) -> anyhow::Result<()> {
    println!("Testing {} (Security Level {}):", name, variant.security_level());
    println!("  Parameters: k={}, l={}", variant.k(), variant.l());
    
    // Generate keypair
    let (pk, sk) = variant.generate_keypair();
    
    // Sign message
    let message = format!("Hello from {}!", name).into_bytes();
    let signed_message = variant.sign_message(&sk, &message)?;
    
    // Verify signature
    let verified_message = variant.verify_signature(&pk, &signed_message)?;
    assert_eq!(message, verified_message);
    
    Ok(())
}

// Test all variants
test_variant(MLDSA44, "ML-DSA-44")?;
test_variant(MLDSA65, "ML-DSA-65")?;
test_variant(MLDSA87, "ML-DSA-87")?;
```

## Dependencies

- [pqcrypto-mldsa](https://github.com/rustpq/pqcrypto) - ML-DSA implementation
- [plonky2](https://github.com/plonky2/plonky2) - Zero-knowledge proof framework
- [anyhow](https://crates.io/crates/anyhow) - Error handling

## License

MIT

