use ark_bls12_381::Fr;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use sha2::{Digest, Sha256};

pub fn generate_nullifier(
    credential_id: Fr,
    server_id: &[u8],
    epoch: u64,
    message_index: u32,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    
    // Serialize credential_id
    let mut id_bytes = Vec::new();
    credential_id.serialize_compressed(&mut id_bytes).unwrap();
    
    hasher.update(&id_bytes);
    hasher.update(server_id);
    hasher.update(&epoch.to_le_bytes());
    hasher.update(&message_index.to_le_bytes());
    
    let hash = hasher.finalize();
    let mut nullifier = [0u8; 32];
    nullifier.copy_from_slice(&hash);
    nullifier
}

pub fn compute_nullifier_coefficient(
    credential_id: Fr,
    server_id: &[u8],
    epoch: u64,
    message_index: u32,
) -> Fr {
    let mut hasher = Sha256::new();
    
    let mut id_bytes = Vec::new();
    credential_id.serialize_compressed(&mut id_bytes).unwrap();
    
    hasher.update(&id_bytes);
    hasher.update(server_id);
    hasher.update(&epoch.to_le_bytes());
    hasher.update(&message_index.to_le_bytes());
    
    let hash = hasher.finalize();
    Fr::from_le_bytes_mod_order(&hash)
}