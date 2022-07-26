use crate::poly::PointPoly;
use bls12_381::{G1Affine, Gt, Scalar};
use group::GroupEncoding;
use secp256kfun::{marker::*, Point, Scalar as ChainScalar};
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Debug, Clone)]
pub struct Message1 {
    pub commits: Vec<Commit>,
}

#[derive(Debug, Clone, Default, Copy)]
pub struct Commit {
    pub C: (G1Affine, Gt),
    pub R: Point,
    pub pad: [u8; 32],
}

#[derive(Debug, Clone, Serialize)]
pub struct Message2 {
    pub bucket_mapping: Vec<usize>,
    pub openings: BTreeSet<usize>,
}

#[derive(Debug, Clone)]
pub struct Message3 {
    pub encryptions: Vec<(crate::dleq::Proof, Gt, ChainScalar<Public, Zero>)>,
    pub polys: Vec<PointPoly>,
    pub openings: Vec<Scalar>,
    pub bit_map_images: Vec<Vec<[Point; 2]>>,
    // there is one of these per outcome ( per oracle )
    pub secret_share_pads_by_oracle: Vec<Vec<ChainScalar<Public, Zero>>>,
}

pub trait EstimateSize {
    fn estimate_size(&self) -> usize;
}

impl EstimateSize for Message1 {
    fn estimate_size(&self) -> usize {
        self.commits.len() * {
            let c = &self.commits[0];
            c.C.0.to_bytes().as_ref().len()
                + c.C.1.to_compressed().as_ref().len()
                + c.R.to_bytes().len()
                + c.pad.len()
        }
    }
}

impl EstimateSize for Message2 {
    fn estimate_size(&self) -> usize {
        bincode::serde::encode_to_vec(&self, bincode::config::standard())
            .unwrap()
            .len()
    }
}

impl EstimateSize for Message3 {
    fn estimate_size(&self) -> usize {
        self.encryptions.len() * {
            let (_proof, gt, scalar) = &self.encryptions[0];
            32 + 32 // proof size
                + gt.to_compressed().as_ref().len()
                + scalar.to_bytes().len()
        } + bincode::serde::encode_to_vec(&self.polys, bincode::config::standard())
            .unwrap()
            .len()
            + self.openings.len() * 32
            + bincode::serde::encode_to_vec(
                &self.secret_share_pads_by_oracle,
                bincode::config::standard(),
            )
            .unwrap()
            .len()
            + bincode::serde::encode_to_vec(&self.bit_map_images, bincode::config::standard())
                .unwrap()
                .len()
    }
}
