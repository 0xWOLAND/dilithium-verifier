
# ML-DSA Verifier - Cargo Workspace

> [!CAUTION]
> **This project has NOT been audited. Use at your own risk.**

A modular implementation of ML-DSA (Module Lattice Digital Signature Algorithm) verifier using Cargo workspaces and zero-knowledge proofs with Plonky2.

## Workspace Structure

The codebase is organized into standalone gadgets:

- **`bit-operations`**: Basic bitwise operations for ZK circuits
- **`shake256`**: SHAKE256 hash function implementation
- **`ntt`**: Number Theoretic Transform operations
- **`mldsa`**: ML-DSA signature verification

## Getting Started

Run tests for all gadgets:
```bash
cargo test
```

Run tests for a specific gadget:
```bash
cargo test -p shake256
cargo test -p ntt
cargo test -p mldsa
cargo test -p bit-operations
```

## Architecture

Each gadget is a standalone crate with:
- Minimal dependencies
- Comprehensive test coverage (TDD approach)
- Clean API for circuit composition
- Zero-knowledge proof compatibility

## Variants

ML-DSA supports three security levels:

| Variant | Security Level | Parameters (k, l) | Public Key Size | Signature Size |
|---------|----------------|-------------------|-----------------|----------------|
| ML-DSA-44 | 2 (128-bit) | (4, 4) | 1312 bytes | ~2420 bytes |
| ML-DSA-65 | 3 (192-bit) | (6, 5) | 1952 bytes | ~3309 bytes |
| ML-DSA-87 | 5 (256-bit) | (8, 7) | 2592 bytes | ~4627 bytes |

## Dependencies

All gadgets use shared workspace dependencies defined in the root `Cargo.toml` for consistency and easier maintenance.

## License

MIT

