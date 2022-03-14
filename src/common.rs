use bls12_381::{
    hash_to_curve::{ExpandMsgXmd, HashToCurve},
    G1Affine, G1Projective,
};
use bls12_381::{multi_miller_loop, G2Prepared, Gt};
use schnorr_fun::fun::marker::*;
use schnorr_fun::fun::Point;
use schnorr_fun::fun::Scalar as ChainScalar;
use sha2::{digest::Digest, Sha256};

#[derive(Clone, Debug)]
pub struct Params {
    pub oracle_key: G2Prepared,
    pub event_id: String,
    pub alice_pk: Point<EvenY>,
    pub bob_pk: Point<EvenY>,
    pub open_proportion: f32,
    pub bucket_size: usize,
    pub n_outcomes: usize,
    pub elgamal_base: Gt,
}

impl Params {
    pub fn M(&self) -> usize {
        ((self.bucket_size * self.n_outcomes) as f32 / self.open_proportion).ceil() as usize
    }

    pub fn anticipated_gt_event_index(&self, event_id: &str, i: usize) -> Gt {
        let M = message_for_event_index(event_id, i);

        multi_miller_loop(&[(&M, &self.oracle_key)]).final_exponentiation()
    }

    pub fn NB(&self) -> usize {
        self.n_outcomes * self.bucket_size
    }

    pub fn num_openings(&self) -> usize {
        self.M() - self.NB()
    }
}

pub fn map_access_GT_to_Zq(ri_mapped: &Gt, ri: &ChainScalar) -> [u8; 32] {
    let mut hashed_xor_ri = Sha256::default()
        .chain(format!("{}", ri_mapped).as_bytes())
        .finalize();
    for (xor_byte, ri_byte) in hashed_xor_ri.iter_mut().zip(ri.to_bytes()) {
        *xor_byte ^= ri_byte
    }
    hashed_xor_ri.try_into().unwrap()
}

pub fn access_Zq(ri_mapped: &Gt, pad: [u8; 32]) -> ChainScalar<Secret, Zero> {
    let mut ri_bytes = Sha256::default()
        .chain(format!("{}", ri_mapped).as_bytes())
        .finalize();
    for (xor_byte, pad_byte) in ri_bytes.iter_mut().zip(pad) {
        *xor_byte ^= pad_byte
    }
    ChainScalar::from_bytes_mod_order(ri_bytes.try_into().unwrap())
}

pub fn message_for_event_index(event_id: &str, i: usize) -> G1Affine {
    <G1Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(
        format!("{}/{}", event_id, i),
        b"dlc-message",
    )
    .into()
}
