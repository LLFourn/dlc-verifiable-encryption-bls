use std::marker::PhantomData;

use bls12_381::{G2Affine, Gt, Scalar};
use ff::Field;
use group::GroupEncoding;
use rand::{CryptoRng, RngCore};
use rand_chacha::ChaCha20Rng;
use sha2::{digest::Update, Sha256};
use sigma_fun::{
    generic_array::{ArrayLength, GenericArray},
    typenum::{self, type_operators::IsLessOrEqual, U31},
    CompactProof, Eq, FiatShamir, HashTranscript, Sigma,
};

/// DL Proof for bls12-381 target group
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DLGT<L> {
    challenge_len: PhantomData<L>,
}

impl<L> sigma_fun::Writable for DLGT<L> {
    fn write_to<W: core::fmt::Write>(&self, w: &mut W) -> core::fmt::Result {
        write!(w, "DL(bls12-381-GT)")
    }
}

impl<L: ArrayLength<u8>> Sigma for DLGT<L>
where
    L: IsLessOrEqual<U31>,
    <L as IsLessOrEqual<U31>>::Output: typenum::marker_traits::NonZero,
{
    type Witness = Scalar;
    type Statement = (Gt, Gt);
    type AnnounceSecret = Scalar;
    type Announcement = Gt;
    type Response = Scalar;
    type ChallengeLength = L;

    fn respond(
        &self,
        witness: &Self::Witness,
        _statement: &Self::Statement,
        announce_secret: Self::AnnounceSecret,
        _announce: &Self::Announcement,
        challenge: &GenericArray<u8, Self::ChallengeLength>,
    ) -> Self::Response {
        let challenge = normalize_challenge(challenge);
        announce_secret + challenge * witness
    }

    fn announce(
        &self,
        statement: &Self::Statement,
        announce_secret: &Self::AnnounceSecret,
    ) -> Self::Announcement {
        let G = &statement.0;
        G * announce_secret
    }

    fn sample_response<Rng: CryptoRng + RngCore>(&self, rng: &mut Rng) -> Self::Response {
        Scalar::random(rng)
    }

    fn implied_announcement(
        &self,
        statement: &Self::Statement,
        challenge: &GenericArray<u8, Self::ChallengeLength>,
        response: &Self::Response,
    ) -> Option<Self::Announcement> {
        let (G, X) = statement;
        let challenge = normalize_challenge(challenge);
        Some(G * response - X * challenge)
    }

    fn hash_statement<H: Update>(&self, hash: &mut H, statement: &Self::Statement) {
        hash.update(format!("{:?}", statement.0).as_bytes());
        hash.update(format!("{:?}", statement.1).as_bytes());
    }

    fn hash_announcement<H: Update>(&self, hash: &mut H, announcement: &Self::Announcement) {
        hash.update(format!("{:?}", announcement).as_bytes());
    }

    fn hash_witness<H: Update>(&self, hash: &mut H, witness: &Self::Witness) {
        hash.update(witness.to_bytes().as_ref())
    }

    fn gen_announce_secret<Rng: CryptoRng + RngCore>(
        &self,
        _witness: &Self::Witness,
        rng: &mut Rng,
    ) -> Self::AnnounceSecret {
        Scalar::random(rng)
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct DLG2<L> {
    challenge_len: PhantomData<L>,
}

impl<L> sigma_fun::Writable for DLG2<L> {
    fn write_to<W: core::fmt::Write>(&self, w: &mut W) -> core::fmt::Result {
        write!(w, "DL(bls12-381-GT)")
    }
}

impl<L: ArrayLength<u8>> Sigma for DLG2<L>
where
    L: IsLessOrEqual<U31>,
    <L as IsLessOrEqual<U31>>::Output: typenum::marker_traits::NonZero,
{
    type Witness = Scalar;
    type Statement = (G2Affine, G2Affine);
    type AnnounceSecret = Scalar;
    type Announcement = G2Affine;
    type Response = Scalar;
    type ChallengeLength = L;

    fn respond(
        &self,
        witness: &Self::Witness,
        _statement: &Self::Statement,
        announce_secret: Self::AnnounceSecret,
        _announce: &Self::Announcement,
        challenge: &GenericArray<u8, Self::ChallengeLength>,
    ) -> Self::Response {
        let challenge = normalize_challenge(challenge);
        announce_secret + challenge * witness
    }

    fn announce(
        &self,
        statement: &Self::Statement,
        announce_secret: &Self::AnnounceSecret,
    ) -> Self::Announcement {
        let G = &statement.0;
        (G * announce_secret).into()
    }

    fn sample_response<Rng: CryptoRng + RngCore>(&self, rng: &mut Rng) -> Self::Response {
        Scalar::random(rng)
    }

    fn implied_announcement(
        &self,
        statement: &Self::Statement,
        challenge: &GenericArray<u8, Self::ChallengeLength>,
        response: &Self::Response,
    ) -> Option<Self::Announcement> {
        let (G, X) = statement;
        let challenge = normalize_challenge(challenge);
        Some((G * response - X * challenge).into())
    }

    fn hash_statement<H: Update>(&self, hash: &mut H, statement: &Self::Statement) {
        hash.update(statement.0.to_bytes());
        hash.update(statement.1.to_bytes());
    }

    fn hash_announcement<H: Update>(&self, hash: &mut H, announcement: &Self::Announcement) {
        hash.update(announcement.to_bytes());
    }

    fn hash_witness<H: Update>(&self, hash: &mut H, witness: &Self::Witness) {
        hash.update(witness.to_bytes().as_ref())
    }

    fn gen_announce_secret<Rng: CryptoRng + RngCore>(
        &self,
        _witness: &Self::Witness,
        rng: &mut Rng,
    ) -> Self::AnnounceSecret {
        Scalar::random(rng)
    }
}

fn normalize_challenge<L: ArrayLength<u8>>(challenge: &GenericArray<u8, L>) -> Scalar {
    let mut challenge_bytes = [0u8; 32];
    challenge_bytes[..challenge.len()].copy_from_slice(challenge.as_slice());
    Scalar::from_bytes(&challenge_bytes).unwrap()
}

type DLEQ = Eq<DLG2<U31>, DLGT<U31>>;

pub type Proof = CompactProof<DLEQ>;

pub type ProofSystem = FiatShamir<DLEQ, HashTranscript<Sha256, ChaCha20Rng>>;

pub fn prove_eqaulity(
    proof_system: &ProofSystem,
    ri_prime: Scalar,
    ri_encryption: Gt,
    sig_point: Gt,
    commit_base: Gt,
    commit: (G2Affine, Gt),
) -> Proof {
    let enc_sub = &ri_encryption - &commit.1;
    let sig_sub = &sig_point - &commit_base;
    let statement = ((G2Affine::generator(), commit.0), (sig_sub, enc_sub));
    let witness = ri_prime;

    let proof = proof_system.prove(&witness, &statement, Some(&mut rand::thread_rng()));
    proof
}

pub fn verify_eqaulity(
    proof_system: &ProofSystem,
    proof: &Proof,
    ri_encryption: Gt,
    sig_point: Gt,
    commit_base: Gt,
    commit: (G2Affine, Gt),
) -> bool {
    let enc_sub = &ri_encryption - &commit.1;
    let sig_sub = &sig_point - &commit_base;
    let statement = ((G2Affine::generator(), commit.0), (sig_sub, enc_sub));

    proof_system.verify(&statement, proof)
}
