use mldsa_verifier::MLDSASigner;

fn main() -> anyhow::Result<()> {
    // Generate keypair
    let (pk, sk) = MLDSASigner::generate_keypair();
    
    // Sign message
    let message = b"Hello ML-DSA!";
    let signed_message = MLDSASigner::sign_message(&sk, message)?;
    
    // Verify signature
    let verified_message = MLDSASigner::verify_signature(&pk, &signed_message)?;
    assert_eq!(message, verified_message.as_slice());
    
    Ok(())
}