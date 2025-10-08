use fua_mcp_zkp::*;
use ark_bls12_381::Fr;
use ark_ff::UniformRand;

fn main() {
    println!("=== FUA-MCP Zero-Knowledge Proof Demo ===\n");
    
    let mut rng = ark_std::test_rng();
    let system = FuaMcpSystem::new();
    
    // Step 1: Issue Credential
    println!("Step 1: Issuing credential with 5 attributes...");
    let attributes = vec![
        Fr::rand(&mut rng),    // [0] user secret
        Fr::from(100u64),      // [1] permission: calendar:read
        Fr::from(200u64),      // [2] permission: email:read  
        Fr::from(999999u64),   // [3] expiry timestamp
        Fr::from(1u64),        // [4] credential version
    ];
    let signature = system.issue_credential(&attributes);
    println!("✓ Credential issued\n");
    
    // Step 2: Generate Verifiable Presentation
    println!("Step 2: Generating verifiable presentation...");
    println!("  - Disclosing only attribute [1] (calendar:read permission)");
    println!("  - Hiding all other attributes including user identity");
    
    let disclosed_indices = vec![1];
    let epoch = 1234567890u64;
    let server_id = b"did:example:mcp-server-12345";
    
    let (vp, metrics) = system.generate_presentation(
        &signature,
        &attributes,
        &disclosed_indices,
        epoch,
        server_id,
    );
    println!("✓ Presentation generated\n");
    
    // Step 3: Verify Presentation
    println!("Step 3: Verifying presentation...");
    let mut seen_nullifiers = std::collections::HashSet::new();
    let (valid, verify_time_ms) = system.verify_presentation(
        &vp,
        epoch,
        server_id,
        &mut seen_nullifiers,
    );
    
    println!("✓ Verification result: {}\n", if valid { "VALID" } else { "INVALID" });
    
    // Step 4: Display Metrics
    println!("=== Performance Metrics ===");
    println!("Prove time:     {:.2} ms", metrics.prove_time_ms);
    println!("Verify time:    {:.2} ms", verify_time_ms);
    println!("Proof size:     {} bytes ({:.2} KB)", 
             metrics.proof_size_bytes, 
             metrics.proof_size_bytes as f64 / 1024.0);
    println!("Gas estimate:   {} units ({:.2} ETH at 50 gwei)", 
             metrics.gas_estimate,
             metrics.gas_estimate as f64 * 50.0 / 1e9);
    
    // Step 5: Test Replay Attack Prevention
    println!("\n=== Testing Replay Attack Prevention ===");
    let (replay_valid, _) = system.verify_presentation(
        &vp,
        epoch,
        server_id,
        &mut seen_nullifiers,
    );
    println!("Replay attempt: {}", if replay_valid { "ACCEPTED (BAD!)" } else { "REJECTED (GOOD!)" });
}