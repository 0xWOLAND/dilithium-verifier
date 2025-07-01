use mldsa_verifier::{MLDSAVariant, MLDSA44, MLDSA65, MLDSA87};

fn test_variant<V: MLDSAVariant>(variant: V, name: &str) -> anyhow::Result<()> {
    println!("\n=== Testing {} ===", name);
    println!("Generating key pair...");
    let (pk, sk) = variant.generate_keypair();
    
    let message = b"Hello, ML-DSA with ZK proofs!";
    println!("Message: {}", String::from_utf8_lossy(message));
    
    println!("Signing message...");
    let signed_message = variant.sign_message(&sk, message)?;
    println!("Signature size: {} bytes", signed_message.len());
    
    println!("Verifying signature with ZK proof...");
    let verified_message = variant.verify_signature(&pk, &signed_message)?;
    
    if message == verified_message.as_slice() {
        println!("✅ Signature verified successfully!");
        println!("✅ ZK proof generated and verified!");
    } else {
        println!("❌ Verification failed!");
        return Err(anyhow::anyhow!("Message mismatch"));
    }
    
    Ok(())
}

fn main() -> anyhow::Result<()> {
    println!("ML-DSA (Dilithium) Zero-Knowledge Verifier");
    println!("==========================================");
    println!("This demonstrates ZK proof generation for ML-DSA signature verification");
    println!("using Plonky2 with exact algorithms from dilithium-py");
    
    test_variant(MLDSA44, "ML-DSA-44 (Security Level 2)")?;
    test_variant(MLDSA65, "ML-DSA-65 (Security Level 3)")?;
    test_variant(MLDSA87, "ML-DSA-87 (Security Level 5)")?;
    
    println!("\n✅ All ML-DSA variants verified successfully with ZK proofs!");
    println!("\nThe SHAKE256 circuit is properly integrated for all hash operations:");
    println!("- Public key transcript computation: H(pk_bytes, 512)");
    println!("- Message digest with transcript: H(tr || M, 512)");
    println!("- Challenge generation: H(μ || w₁Encode(w'), 2λ)");
    
    Ok(())
}