use criterion::{black_box, criterion_group, criterion_main, Criterion};
use fua_mcp_zkp::*;
use ark_bls12_381::Fr;
use ark_ff::UniformRand;

fn benchmark_credential_issuance(c: &mut Criterion) {
    let mut rng = ark_std::test_rng();
    let system = FuaMcpSystem::new();
    
    let attributes: Vec<Fr> = (0..5).map(|_| Fr::rand(&mut rng)).collect();
    
    c.bench_function("credential_issuance", |b| {
        b.iter(|| {
            system.issue_credential(black_box(&attributes))
        })
    });
}

fn benchmark_presentation_generation(c: &mut Criterion) {
    let mut rng = ark_std::test_rng();
    let system = FuaMcpSystem::new();
    
    let attributes: Vec<Fr> = (0..5).map(|_| Fr::rand(&mut rng)).collect();
    let signature = system.issue_credential(&attributes);
    let disclosed_indices = vec![1];
    let epoch = 1234567890u64;
    let server_id = b"did:example:mcp-server";
    
    c.bench_function("presentation_generation", |b| {
        b.iter(|| {
            system.generate_presentation(
                black_box(&signature),
                black_box(&attributes),
                black_box(&disclosed_indices),
                black_box(epoch),
                black_box(server_id),
            )
        })
    });
}

fn benchmark_presentation_verification(c: &mut Criterion) {
    let mut rng = ark_std::test_rng();
    let system = FuaMcpSystem::new();
    
    let attributes: Vec<Fr> = (0..5).map(|_| Fr::rand(&mut rng)).collect();
    let signature = system.issue_credential(&attributes);
    let disclosed_indices = vec![1];
    let epoch = 1234567890u64;
    let server_id = b"did:example:mcp-server";
    
    let (vp, _) = system.generate_presentation(
        &signature,
        &attributes,
        &disclosed_indices,
        epoch,
        server_id,
    );
    
    c.bench_function("presentation_verification", |b| {
        let mut seen_nullifiers = std::collections::HashSet::new();
        b.iter(|| {
            seen_nullifiers.clear();
            system.verify_presentation(
                black_box(&vp),
                black_box(epoch),
                black_box(server_id),
                &mut seen_nullifiers,
            )
        })
    });
}

criterion_group!(
    benches,
    benchmark_credential_issuance,
    benchmark_presentation_generation,
    benchmark_presentation_verification
);
criterion_main!(benches);