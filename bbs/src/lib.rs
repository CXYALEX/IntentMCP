use ark_bls12_381::Fr;
use ark_serialize::CanonicalSerialize;
use std::time::Instant;

pub mod bbs_plus;
pub mod zkp;
pub mod nullifier;

use bbs_plus::*;
use zkp::*;
use nullifier::*;

#[derive(Debug, Clone)]
pub struct PerformanceMetrics {
    pub prove_time_ms: f64,
    pub verify_time_ms: f64,
    pub proof_size_bytes: usize,
    pub gas_estimate: u64,
}

pub struct FuaMcpSystem {
    pub issuer_keypair: BBSPlusKeypair,
}

impl FuaMcpSystem {
    pub fn new() -> Self {
        let mut rng = ark_std::test_rng();
        let issuer_keypair = BBSPlusKeypair::generate(&mut rng, 5);
        Self { issuer_keypair }
    }

    pub fn issue_credential(
        &self,
        attributes: &[Fr],
    ) -> BBSPlusSignature {
        let mut rng = ark_std::test_rng();
        self.issuer_keypair.sign(&mut rng, attributes)
    }

    pub fn generate_presentation(
        &self,
        signature: &BBSPlusSignature,
        attributes: &[Fr],
        disclosed_indices: &[usize],
        _epoch: u64,
        _server_id: &[u8],
    ) -> (VerifiablePresentation, PerformanceMetrics) {
        let start = Instant::now();
        
        let mut rng = ark_std::test_rng();
        
        // Randomize signature
        let randomized_sig = signature.randomize(&mut rng);
        
        // Generate nullifier
        let credential_id = attributes[0];
        let nullifier = generate_nullifier(credential_id, _server_id, _epoch, 0);
        
        // Generate ZK proof
        let proof = generate_zkp(
            &randomized_sig,
            attributes,
            disclosed_indices,
            &self.issuer_keypair.public_key,
        );
        
        let prove_time = start.elapsed();
        
        let vp = VerifiablePresentation {
            randomized_signature: randomized_sig,
            nullifier,
            proof,
            disclosed_attributes: disclosed_indices
                .iter()
                .map(|&i| (i, attributes[i]))
                .collect(),
        };
        
        // Calculate proof size
        let mut proof_bytes = Vec::new();
        vp.serialize_compressed(&mut proof_bytes).unwrap();
        let proof_size = proof_bytes.len();
        
        let metrics = PerformanceMetrics {
            prove_time_ms: prove_time.as_secs_f64() * 1000.0,
            verify_time_ms: 0.0, // Will be filled during verification
            proof_size_bytes: proof_size,
            gas_estimate: estimate_gas(proof_size),
        };
        
        (vp, metrics)
    }

    pub fn verify_presentation(
        &self,
        vp: &VerifiablePresentation,
        _epoch: u64,
        _server_id: &[u8],
        seen_nullifiers: &mut std::collections::HashSet<[u8; 32]>,
    ) -> (bool, f64) {
        let start = Instant::now();
        
        // Check nullifier hasn't been used
        if seen_nullifiers.contains(&vp.nullifier) {
            return (false, start.elapsed().as_secs_f64() * 1000.0);
        }
        
        // Verify ZK proof
        let valid = verify_zkp(
            &vp.proof,
            &vp.randomized_signature,
            &vp.disclosed_attributes,
            &self.issuer_keypair.public_key,
        );
        
        if valid {
            seen_nullifiers.insert(vp.nullifier);
        }
        
        let verify_time = start.elapsed().as_secs_f64() * 1000.0;
        (valid, verify_time)
    }
}

fn estimate_gas(proof_size_bytes: usize) -> u64 {
    // Rough estimate based on Ethereum gas costs
    let base_cost = 21000u64;
    let calldata_cost = (proof_size_bytes as u64) * 16; // 16 gas per byte
    let verification_cost = 500000u64; // Pairing operations are expensive
    
    base_cost + calldata_cost + verification_cost
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;

    #[test]
    fn test_full_flow() {
        let mut rng = ark_std::test_rng();
        let system = FuaMcpSystem::new();
        
        // Issue credential
        let attributes = vec![
            Fr::rand(&mut rng), // user secret
            Fr::from(1u64),     // permission: calendar:read
            Fr::from(2u64),     // permission: email:read
            Fr::from(100u64),   // expiry timestamp
            Fr::from(1u64),     // credential version
        ];
        
        let signature = system.issue_credential(&attributes);
        
        // Generate presentation
        let disclosed_indices = vec![1]; // Only reveal calendar:read permission
        let epoch = 1234567890u64;
        let server_id = b"did:example:mcp-server-12345";
        
        let (vp, mut metrics) = system.generate_presentation(
            &signature,
            &attributes,
            &disclosed_indices,
            epoch,
            server_id,
        );
        
        // Verify presentation
        let mut seen_nullifiers = std::collections::HashSet::new();
        let (valid, verify_time) = system.verify_presentation(
            &vp,
            epoch,
            server_id,
            &mut seen_nullifiers,
        );
        
        metrics.verify_time_ms = verify_time;
        
        assert!(valid);
        println!("\n=== Performance Metrics ===");
        println!("Prove time: {:.2} ms", metrics.prove_time_ms);
        println!("Verify time: {:.2} ms", metrics.verify_time_ms);
        println!("Proof size: {} bytes", metrics.proof_size_bytes);
        println!("Gas estimate: {} units", metrics.gas_estimate);
    }
}