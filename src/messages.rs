use crate::poly::PointPoly;
use bls12_381::{G2Affine, Gt, Scalar};
use secp256kfun::{marker::*, Point, Scalar as ChainScalar};
// use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Debug, Clone)]
pub struct Message1 {
    pub commits: Vec<Commit>,
}

#[derive(Debug, Clone, Default, Copy)]
pub struct Commit {
    pub C: (G2Affine, Gt),
    pub R: Point,
    pub pad: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct Message2 {
    pub bucket_mapping: Vec<usize>,
    pub openings: BTreeSet<usize>,
}

#[derive(Debug, Clone)]
pub struct Message3 {
    pub encryptions: Vec<(crate::dleq::Proof, Gt, ChainScalar<Secret, Zero>)>,
    pub polys: Vec<PointPoly>,
    pub openings: Vec<Scalar>,
}
