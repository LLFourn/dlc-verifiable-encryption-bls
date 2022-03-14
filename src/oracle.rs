use bls12_381::{G1Affine, G2Affine, G2Prepared, Scalar};

use crate::common::message_for_event_index;

#[allow(dead_code)]
pub struct Oracle {
    sk: Scalar,
    pk: G2Prepared,
}

impl Oracle {
    pub fn new(scalar: Scalar) -> Self {
        Self {
            sk: scalar,
            pk: G2Prepared::from(G2Affine::from(G2Affine::generator() * scalar)),
        }
    }

    pub fn public_key(&self) -> G2Prepared {
        self.pk.clone()
    }

    pub fn attest(&self, event_id: &str, i: usize) -> G1Affine {
        let message = message_for_event_index(event_id, i);
        G1Affine::from(&message * &self.sk)
    }
}
