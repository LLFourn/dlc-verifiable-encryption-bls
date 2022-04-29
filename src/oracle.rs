use bls12_381::{G1Affine, G2Affine, Scalar};
use ff::Field;
use rand::RngCore;

use crate::common::message_for_event_index;

#[allow(dead_code)]
pub struct Oracle {
    sk: Scalar,
    pk: G1Affine,
}

impl Oracle {
    pub fn random(rng: &mut impl RngCore) -> Self {
        Self::new(Scalar::random(rng))
    }
    pub fn new(scalar: Scalar) -> Self {
        Self {
            sk: scalar,
            pk: G1Affine::from(G1Affine::generator() * scalar),
        }
    }

    pub fn public_key(&self) -> G1Affine {
        self.pk.clone()
    }

    pub fn attest(&self, event_id: &str, outcome_index: u32) -> G2Affine {
        let message = message_for_event_index(event_id, outcome_index);
        let sig = G2Affine::from(&message * &self.sk);
        sig
    }
}
