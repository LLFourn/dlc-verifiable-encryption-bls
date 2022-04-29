use bls12_381::{G1Affine, G2Affine, G2Prepared, Scalar};
use ff::Field;
use rand::RngCore;

use crate::common::message_for_event_index;

#[allow(dead_code)]
pub struct Oracle {
    sk: Scalar,
    pk: G2Prepared,
}

impl Oracle {
    pub fn random(rng: &mut impl RngCore) -> Self {
        Self::new(Scalar::random(rng))
    }
    pub fn new(scalar: Scalar) -> Self {
        Self {
            sk: scalar,
            pk: G2Prepared::from(G2Affine::from(G2Affine::generator() * scalar)),
        }
    }

    pub fn public_key(&self) -> G2Prepared {
        self.pk.clone()
    }

    pub fn attest(&self, event_id: &str, outcome_index: u32) -> G1Affine {
        let message = message_for_event_index(event_id, outcome_index);
        let sig = G1Affine::from(&message * &self.sk);
        sig
    }
}
