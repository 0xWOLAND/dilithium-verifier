use mldsa_verifier::{MLDSAVariant, MLDSA44, MLDSA65, MLDSA87};

fn test_variant<V: MLDSAVariant>(variant: V) -> anyhow::Result<()> {
    let (pk, sk) = variant.generate_keypair();
    let message = b"test";
    let signed_message = variant.sign_message(&sk, message)?;
    let verified_message = variant.verify_signature(&pk, &signed_message)?;
    assert_eq!(message, verified_message.as_slice());
    Ok(())
}

fn main() -> anyhow::Result<()> {
    test_variant(MLDSA44)?;
    test_variant(MLDSA65)?;
    test_variant(MLDSA87)?;
    Ok(())
}