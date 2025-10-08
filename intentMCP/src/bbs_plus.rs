use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, Group};
use ark_ff::{Field, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct BBSPlusPublicKey {
    pub w: G2Affine,
    pub h: Vec<G1Affine>,
    pub g1: G1Affine,
    pub g2: G2Affine,
}

#[derive(Clone)]
pub struct BBSPlusKeypair {
    pub secret_key: Fr,
    pub public_key: BBSPlusPublicKey,
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct BBSPlusSignature {
    pub a: G1Affine,
    pub e: Fr,
    pub s: Fr,
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct RandomizedSignature {
    pub a_prime: G1Affine,
    pub a_bar: G1Affine,
    pub b_prime_prime: G1Affine,
    pub s_prime: Fr,
    pub r3: Fr,
}

impl BBSPlusKeypair {
    pub fn generate<R: Rng>(rng: &mut R, num_attributes: usize) -> Self {
        let secret_key = Fr::rand(rng);
        let g1 = G1Projective::rand(rng).into_affine();
        let g2 = G2Projective::rand(rng).into_affine();
        
        // Use Group::generator() instead
        let w = (G2Projective::generator() * secret_key).into_affine();
        
        let h: Vec<G1Affine> = (0..=num_attributes)
            .map(|_| G1Projective::rand(rng).into_affine())
            .collect();
        
        let public_key = BBSPlusPublicKey { w, h, g1, g2 };
        
        Self { secret_key, public_key }
    }

    pub fn sign<R: Rng>(&self, rng: &mut R, messages: &[Fr]) -> BBSPlusSignature {
        let e = Fr::rand(rng);
        let s = Fr::rand(rng);
        
        // Compute B = g1 * h0^s * h1^m1 * h2^m2 * ...
        let mut b = G1Projective::from(self.public_key.g1);
        b += G1Projective::from(self.public_key.h[0]) * s;
        
        for (i, m) in messages.iter().enumerate() {
            b += G1Projective::from(self.public_key.h[i + 1]) * m;
        }
        
        // A = B^(1/(e+x))
        let exp = (e + self.secret_key).inverse().unwrap();
        let a = (b * exp).into_affine();
        
        BBSPlusSignature { a, e, s }
    }

    pub fn verify(&self, signature: &BBSPlusSignature, messages: &[Fr]) -> bool {
        // Compute B
        let mut b = G1Projective::from(self.public_key.g1);
        b += G1Projective::from(self.public_key.h[0]) * signature.s;
        
        for (i, m) in messages.iter().enumerate() {
            b += G1Projective::from(self.public_key.h[i + 1]) * m;
        }
        
        // Check e(A, w * g2^e) = e(B, g2)
        let w_g2e = (G2Projective::from(self.public_key.w) + 
                     G2Projective::from(self.public_key.g2) * signature.e).into_affine();
        
        let lhs = Bls12_381::pairing(signature.a, w_g2e);
        let rhs = Bls12_381::pairing(b, self.public_key.g2);
        
        lhs == rhs
    }
}

impl BBSPlusSignature {
    pub fn randomize<R: Rng>(&self, rng: &mut R) -> RandomizedSignature {
        let r1 = Fr::rand(rng);
        let r2 = Fr::rand(rng);
        let r3 = r1.inverse().unwrap();
        
        let a_prime = (G1Projective::from(self.a) * r1).into_affine();
        let a_bar = (G1Projective::from(a_prime) * (-self.e)).into_affine();
        
        // This is a simplified version
        let b_prime_prime = (G1Projective::from(self.a) * r1).into_affine();
        let s_prime = self.s - r2 * r3;
        
        RandomizedSignature {
            a_prime,
            a_bar,
            b_prime_prime,
            s_prime,
            r3,
        }
    }
}