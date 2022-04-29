use rand::{CryptoRng, RngCore};
use secp256kfun::{g, marker::*, op, s, Point, Scalar, G};
use serde::Serialize;
use std::iter;

#[derive(Clone, Debug, PartialEq)]
pub struct ScalarPoly(Vec<Scalar>);

impl ScalarPoly {
    pub fn eval(&self, x: u32) -> Scalar<Secret, Zero> {
        let x = Scalar::from(x)
            .expect_nonzero("must be non-zero")
            .mark::<Public>();
        let mut xpow = s!(1).mark::<Public>();
        self.0
            .iter()
            .skip(1)
            .fold(self.0[0].clone().mark::<Zero>(), move |sum, coeff| {
                xpow = s!(xpow * x).mark::<Public>();
                s!(sum + xpow * coeff)
            })
    }

    pub fn to_point_poly(&self) -> PointPoly {
        PointPoly(self.0.iter().map(|a| g!(a * G).normalize()).collect())
    }

    pub fn random(n_coefficients: usize, rng: &mut (impl RngCore + CryptoRng)) -> Self {
        ScalarPoly((0..n_coefficients).map(|_| Scalar::random(rng)).collect())
    }

    pub fn poly_len(&self) -> usize {
        self.0.len()
    }

    pub fn new(x: Vec<Scalar>) -> Self {
        Self(x)
    }

    pub fn pop_front(&mut self) {
        self.0.remove(0);
    }

    pub fn push_front(&mut self, scalar: Scalar) {
        self.0.insert(0, scalar)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PointPoly(Vec<Point<Normal, Public, NonZero>>);

impl PointPoly {
    pub fn eval(&self, x: u32) -> Point<Jacobian, Public, Zero> {
        let x = Scalar::from(x)
            .expect_nonzero("must be non-zero")
            .mark::<Public>();
        let xpows = iter::successors(Some(s!(1).mark::<Public>()), |xpow| {
            Some(s!(x * xpow).mark::<Public>())
        })
        .take(self.0.len())
        .collect::<Vec<_>>();
        op::lincomb(&xpows, &self.0)
    }

    pub fn poly_len(&self) -> usize {
        self.0.len()
    }

    pub fn points(&self) -> &[Point<Normal, Public, NonZero>] {
        &self.0
    }

    pub fn pop_front(&mut self) {
        self.0.remove(0);
    }

    pub fn push_front(&mut self, point: Point<Normal, Public, NonZero>) {
        self.0.insert(0, point)
    }
}
