use bls12_381::{
    hash_to_curve::{ExpandMsgXmd, HashToCurve},
    pairing, G1Affine, G2Affine, G2Projective,
};
use bls12_381::{multi_miller_loop, G1Projective, G2Prepared, Gt};
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
    pub g2_prepared: G2Prepared,
}

impl Params {
    pub fn M(&self) -> usize {
        (self.NB() as f64 / self.closed_proportion).ceil() as usize
    }

    pub fn n_outcome_bits(&self) -> u32 {
        (self.n_outcomes as f32).log2().ceil() as u32
    }

    pub fn n_anticipations_per_oracle(&self) -> u32 {
        self.n_outcome_bits() * 2
    }

    pub fn NB(&self) -> usize {
        self.bucket_size as usize
            * self.n_anticipations_per_oracle() as usize
            * self.oracle_keys.len()
    }

    pub fn num_openings(&self) -> usize {
        self.M() - self.NB()
    }

    pub fn iter_anticipations(&self, oracle_index: usize) -> impl Iterator<Item = [Gt; 2]> + '_ {
        (0..self.n_outcome_bits()).map(move |bit| {
            [
                self.anticipate_at_index(oracle_index, bit, false),
                self.anticipate_at_index(oracle_index, bit, true),
            ]
        })
    }

    pub fn anticipate_at_index(
        &self,
        oracle_index: usize,
        outcome_bit_index: u32,
        outcome_bit_value: bool,
    ) -> Gt {
        let message = message_for_event_index(&self.event_id, outcome_bit_index, outcome_bit_value);
        pairing(&self.oracle_keys[oracle_index as usize], &message)
    }

    pub fn verify_bls_sig(
        &self,
        oracle_index: usize,
        outcome_bit_index: u32,
        outcome_bit_value: bool,
        sig: G2Affine,
    ) -> bool {
        let gt = pairing(&G1Affine::generator(), &sig);
        let expected = self.anticipate_at_index(oracle_index, outcome_bit_index, outcome_bit_value);
        gt == expected
    }

    pub fn map_Zq_to_Gt(&self, ri: &ChainScalar) -> (Gt, [u8; 32]) {
        let gt_elem = {
            let g1 = G1Affine::from(G1Projective::random(&mut rand::thread_rng()));
            multi_miller_loop(&[(&g1, &self.g2_prepared)]).final_exponentiation()
        };
        let mut hashed_xor_ri = Sha256::default().chain(gt_elem.to_compressed()).finalize();
        for (xor_byte, ri_byte) in hashed_xor_ri.iter_mut().zip(ri.to_bytes()) {
            *xor_byte ^= ri_byte
        }
        (gt_elem, hashed_xor_ri.try_into().unwrap())
    }
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

pub fn message_for_event_index(
    event_id: &str,
    outcome_bit_index: u32,
    outcome_bit_value: bool,
) -> G2Affine {
    <G2Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(
        format!("{}/{}/{}", event_id, outcome_bit_index, outcome_bit_value),
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
    let mut n_encryptions = n_outcomes.log2().ceil() * 2.0;
    if n_encryptions == 0.0 {
        n_encryptions = 1.0;
    }
    let n_oracles = n_oracles as f64;
    let N = n_encryptions * n_oracles;
    // we can afford to remove 1 bit of security since for any corruption the adversary makes there
    // is a 1/2 chance that that outcome is actually selected.
    let s = security_param as f64 - 1.0;

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

pub fn to_bits(mut num: u32, bit_length: usize) -> Vec<bool> {
    (0..bit_length)
        .map(|_| {
            let bit = num & 0x01 == 1;
            num = num >> 1;
            bit
        })
        .collect()
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_to_bits() {
        assert_eq!(to_bits(0x01, 2), vec![true, false]);
        assert_eq!(to_bits(0x3, 2), vec![true, true]);
    }
}
