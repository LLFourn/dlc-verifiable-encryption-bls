use bls12_381::pairing as e;
use bls12_381::{
    hash_to_curve::{ExpandMsgXmd, HashToCurve},
    G1Projective, G2Affine,
};
use clap::Parser;
use dlc_venc_pairing::messages::EstimateSize;
use dlc_venc_pairing::{
    alice::*,
    bob::*,
    common::{compute_optimal_params, Params},
    oracle::Oracle,
};
use rand::Rng;
use secp256kfun::{g, Scalar as ChainScalar, G};
use sha2::Sha256;
use std::time::Instant;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct CliArgs {
    /// The security parameter (how many bits of security for the overall protocol)
    #[clap(short, default_value_t = 30)]
    s: u8,
    /// The number of outcomes
    #[clap(long)]
    n_outcomes: u32,
    /// The number of oracles
    #[clap(long)]
    n_oracles: u16,
    /// The threshold of oracles that is required to attest
    #[clap(long)]
    threshold: u16,
}

fn main() -> anyhow::Result<()> {
    let args = CliArgs::parse();
    let elgamal_base =
        <G1Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(b"dlc".as_ref(), b"dlc");

    let elgamal_base = e(&elgamal_base.into(), &G2Affine::generator());

    let oracles = (0..args.n_oracles)
        .map(|_| Oracle::random(&mut rand::thread_rng()))
        .collect::<Vec<_>>();

    let (closed_proportion, bucket_size) =
        compute_optimal_params(args.s, args.n_outcomes as u32, args.n_oracles as u32);

    let params = Params {
        oracle_keys: oracles.iter().map(|oracle| oracle.public_key()).collect(),
        n_outcomes: args.n_outcomes,
        bucket_size,
        closed_proportion,
        elgamal_base,
        threshold: args.threshold,
        event_id: "test".to_string(),
    };

    let secrets = (0..params.n_outcomes)
        .map(|_| ChainScalar::random(&mut rand::thread_rng()))
        .collect::<Vec<_>>();
    let secret_images = secrets.iter().map(|s| g!(s * G).normalize()).collect();

    println!("Params s: {} n_oracles: {} n_outcomes: {} threshold: {} n_encryptions: {} bucket_size: {} proportion_closed: {}",
             args.s, args.n_oracles, args.n_outcomes, args.threshold, params.M(), params.bucket_size, params.closed_proportion);
    let start_round1 = Instant::now();
    let (alice, m1) = Alice1::new(&params);
    let m1_encode_len = encode_len(&m1);
    println!(
        "End round 1 elapsed: {:?} transmitted: {}",
        start_round1.elapsed(),
        m1_encode_len
    );
    let start_round2 = Instant::now();
    let (bob, m2) = Bob1::new(m1, &params)?;
    let m2_encode_len = encode_len(&m2);
    println!(
        "End round 2 elapsed: {:?} transmitted: {}",
        start_round2.elapsed(),
        m2_encode_len
    );
    let start_round3 = Instant::now();
    let m3 = alice.receive_message(m2, secrets, &params)?;
    let m3_encode_len = encode_len(&m3);
    println!(
        "End round 3 elapsed: {:?} transmitted: {}",
        start_round3.elapsed(),
        m3_encode_len
    );
    let start_round4 = Instant::now();
    let bob = bob.receive_message(m3, secret_images, &params)?;
    println!("End round 4 elapsed: {:?}", start_round4.elapsed());

    let total_transmit_interactive = m1_encode_len + m2_encode_len + m3_encode_len;
    let total_transmit_non_interactive = m1_encode_len + m3_encode_len;

    println!(
        "Total elapsed: {:?} sans-preprocessing: {:?} transmitted: {} non-interactive: {}",
        start_round1.elapsed(),
        start_round2.elapsed(),
        total_transmit_interactive,
        total_transmit_non_interactive
    );

    let outcome_index = rand::thread_rng().gen_range(0..args.n_outcomes);

    let attestations = oracles
        .iter()
        .map(|oracle| oracle.attest(&params.event_id, outcome_index))
        .collect();
    println!("got attestation");
    let scalar = bob.receive_oracle_attestation(outcome_index, attestations, &params)?;

    println!("got the secret {}", scalar);

    Ok(())
}

fn encode_len(message: &impl EstimateSize) -> usize {
    message.estimate_size()
}
