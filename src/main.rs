use mldsa_verifier::{MLDSAVariant, MLDSA44, MLDSA65, MLDSA87};

fn test_variant<V: MLDSAVariant>(variant: V, name: &str) -> anyhow::Result<()> {
    let (pk, sk) = variant.generate_keypair();
    let message = b"test";
    let signed_message = variant.sign_message(&sk, message)?;
    let verified_message = variant.verify_signature(&pk, &signed_message)?;
    if message == verified_message.as_slice() {
        println!("{}: ok", name);
        Ok(())
    } else {
        Err(anyhow::anyhow!("Verification failed for {}", name))
    }
}

fn main() -> anyhow::Result<()> {
    println!("Testing ML-DSA-44");
    test_variant(MLDSA44, "ML-DSA-44")?;
    println!("Testing ML-DSA-65");
    test_variant(MLDSA65, "ML-DSA-65")?;
    println!("Testing ML-DSA-87");
    test_variant(MLDSA87, "ML-DSA-87")?;
    Ok(())
}