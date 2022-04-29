use bls12_381::Gt;
use bls12_381::{
    hash_to_curve::{ExpandMsgXmd, HashToCurve},
    pairing, G1Affine, G2Affine, G2Projective, Scalar,
};
use ff::Field;
use group::Group;
use secp256kfun::marker::*;
use secp256kfun::Scalar as ChainScalar;
use sha2::{digest::Digest, Sha256};

#[derive(Clone, Debug)]
pub struct Params {
    pub oracle_keys: Vec<G1Affine>,
    pub event_id: String,
    pub closed_proportion: f64,
    pub bucket_size: u8,
    pub n_outcomes: u32,
    pub threshold: u16,
    pub elgamal_base: Gt,
}

impl Params {
    pub fn M(&self) -> usize {
        (self.NB() as f64 / self.closed_proportion).ceil() as usize
    }

    pub fn NB(&self) -> usize {
        self.bucket_size as usize * self.n_outcomes as usize * self.oracle_keys.len()
    }

    pub fn num_openings(&self) -> usize {
        self.M() - self.NB()
    }

    pub fn iter_anticipations(&self, oracle_index: usize) -> impl Iterator<Item = Gt> + '_ {
        (0..self.n_outcomes)
            .map(move |outcome_index| self.anticipate_at_index(oracle_index, outcome_index))
    }

    pub fn anticipate_at_index(&self, oracle_index: usize, outcome_index: u32) -> Gt {
        let message = message_for_event_index(&self.event_id, outcome_index);
        pairing(&self.oracle_keys[oracle_index as usize], &message)
    }

    pub fn verify_bls_sig(&self, oracle_index: usize, outcome_index: u32, sig: G2Affine) -> bool {
        let gt = pairing(&G1Affine::generator(), &sig);
        let expected = self.anticipate_at_index(oracle_index, outcome_index);
        gt == expected
    }
}

pub fn map_Zq_to_Gt(ri: &ChainScalar) -> (Gt, [u8; 32]) {
    let gt_elem = {
        let scalar = Scalar::random(&mut rand::thread_rng());
        &Gt::generator() * &scalar
    };
    let mut hashed_xor_ri = Sha256::default().chain(gt_elem.to_compressed()).finalize();
    for (xor_byte, ri_byte) in hashed_xor_ri.iter_mut().zip(ri.to_bytes()) {
        *xor_byte ^= ri_byte
    }
    (gt_elem, hashed_xor_ri.try_into().unwrap())
}

pub fn map_Gt_to_Zq(ri_mapped: &Gt, pad: [u8; 32]) -> ChainScalar<Secret, Zero> {
    let mut ri_bytes = Sha256::default()
        .chain(ri_mapped.to_compressed())
        .finalize();
    for (xor_byte, pad_byte) in ri_bytes.iter_mut().zip(pad) {
        *xor_byte ^= pad_byte
    }
    ChainScalar::from_bytes_mod_order(ri_bytes.try_into().unwrap())
}

pub fn message_for_event_index(event_id: &str, i: u32) -> G2Affine {
    <G2Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(
        format!("{}/{}", event_id, i),
        b"dlc-message",
    )
    .into()
}

pub fn compute_optimal_params(security_param: u8, n_outcomes: u32, n_oracles: u32) -> (f64, u8) {
    if n_outcomes * n_oracles == 1 {
        // this is cheating and not quite right
        return (0.5, security_param);
    }
    let n_outcomes = n_outcomes as f64;
    let n_oracles = n_oracles as f64;
    let N = n_outcomes * n_oracles;
    let s = security_param as f64;
    // In order to actually succeed the adversary most corrupt a bucket the chosen outcome. This
    // happens with (1/<number of outcomes>) probability so we can relax overall security parameter
    // by log2(<number of outcomes>).
    let s = s - n_outcomes.log2();

    let (B, p, _) = (500..999)
        .filter_map(|p| {
            let p = (p as f64) / 1000.0;
            // requirement for the formula below to hold
            if N < (1.0 / (1.0 - p)) {
                return None;
            }
            let B = ((s as f64 + (N as f64).log2() - p.log2())
                / ((N - N * p).log2() - p.log2() / (1.0 - p)))
                .ceil();
            let score = ((B * N) / p).ceil() as u64;
            Some((B as u8, p, score))
        })
        .min_by_key(|(_, _, score)| *score)
        .unwrap();

    (p, B)
}
