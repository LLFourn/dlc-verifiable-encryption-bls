use bls12_381::{
    hash_to_curve::{ExpandMsgXmd, HashToCurve},
    G1Projective, G2Affine,
};
use bls12_381::{pairing as e, Scalar};
use dlc_venc::{alice::*, bob::*, common::Params, oracle::Oracle};
use schnorr_fun::{
    fun::{g, s, Scalar as ChainScalar, G},
    nonce::Deterministic,
    Schnorr,
};
use sha2::Sha256;

fn main() -> anyhow::Result<()> {
    let oracle_sk = Scalar::from_bytes(&[42u8; 32]).unwrap();
    let oracle = Oracle::new(oracle_sk);
    let oracle_key = oracle.public_key();
    let schnorr = Schnorr::<Sha256, Deterministic<Sha256>>::default();
    let alice_keypair = schnorr.new_keypair(s!(3));
    let bob_keypair = schnorr.new_keypair(s!(5));
    let elgamal_base =
        <G1Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(b"dlc".as_ref(), b"dlc");
    let elgamal_base = e(&elgamal_base.into(), &G2Affine::generator());
    let params = Params {
        oracle_key,
        n_outcomes: 1024,
        event_id: "test".to_string(),
        alice_pk: alice_keypair.verification_key(),
        bob_pk: bob_keypair.verification_key(),
        bucket_size: 6,
        open_proportion: 0.85,
        elgamal_base,
    };

    println!("alice round 1");
    let (alice, m1) = Alice1::new(&params);
    println!("bob round 2");
    let (bob, m2) = Bob1::new(m1, &params)?;
    let secret_sigs = (0..params.n_outcomes)
        .map(|_| ChainScalar::random(&mut rand::thread_rng()))
        .collect::<Vec<_>>();
    let anticipated_sigs = secret_sigs.iter().map(|s| g!(s * G).normalize()).collect();
    println!("alice round 3");
    let (_, m3) = alice.receive_message(m2, secret_sigs, &params)?;
    println!("bob round 4");
    let bob = bob.receive_message(m3, anticipated_sigs, &params)?;

    let attestation = oracle.attest(&params.event_id, 42);
    println!("attestation");
    let scalar = bob.receive_oracle_attestation(42, attestation)?;

    println!("got the secret sig {}", scalar);

    Ok(())
}
