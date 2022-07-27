use crate::{common::Params, messages::*};
use anyhow::anyhow;
use bls12_381::{G1Affine, Gt, Scalar};
use ff::Field;
use secp256kfun::{g, marker::*, s, Scalar as ChainScalar, G};

pub struct Alice1 {
    commit_secrets: Vec<(ChainScalar, Scalar, Gt)>,
    commits: Vec<Commit>,
}

impl Alice1 {
    pub fn new(params: &Params) -> (Alice1, Message1) {
        let (commits, commit_secrets): (Vec<Commit>, Vec<(ChainScalar, Scalar, Gt)>) = (0..params
            .M())
            .map(|_| {
                // hackily map elements of Z_q to G_t
                let (hashed_xor_ri, ri, ri_mapped) = {
                    let ri = ChainScalar::random(&mut rand::thread_rng());
                    let (ri_mapped, pad) = params.map_Zq_to_Gt(&ri);
                    (pad, ri, ri_mapped)
                };

                let Ri = g!(ri * G).normalize();
                let ri_prime = Scalar::random(&mut rand::thread_rng());
                // Create Elgamal comitments in the form of (G_1, G_T)
                let C_i = (
                    (G1Affine::generator() * &ri_prime).into(),
                    (&params.elgamal_base * ri_prime) + &ri_mapped,
                );

                (
                    Commit {
                        C: C_i,
                        R: Ri,
                        pad: hashed_xor_ri.try_into().unwrap(),
                    },
                    (ri, ri_prime, ri_mapped),
                )
            })
            .unzip();

        (
            Alice1 {
                commit_secrets,
                commits: commits.clone(),
            },
            Message1 { commits },
        )
    }

    pub fn receive_message(
        self,
        message: Message2,
        secrets: Vec<ChainScalar>,
        params: &Params,
    ) -> anyhow::Result<Message3> {
        let NB = params.NB();
        if let Some(bad_index) = message.bucket_mapping.iter().find(|map| **map >= NB) {
            return Err(anyhow!(
                "bucket was mapped to {} which is outside of range 0..{}",
                bad_index,
                NB
            ));
        }

        if message.openings.len() != params.num_openings() {
            return Err(anyhow!(
                "wrong number of openings requested. Expected {} got {}",
                params.num_openings(),
                message.openings.len()
            ));
        }

        let Alice1 {
            mut commit_secrets,
            mut commits,
        } = self;

        let mut i = 0;
        commits.retain(|_| {
            let open_it = message.openings.contains(&i);
            i += 1;
            !open_it
        });

        let mut i = 0;
        let mut openings = vec![];
        commit_secrets.retain(|secret| {
            let open_it = message.openings.contains(&i);
            i += 1;
            if open_it {
                openings.push(secret.1.clone());
            }
            !open_it
        });

        let mut buckets = Vec::with_capacity(params.NB());

        for from in message.bucket_mapping.into_iter() {
            buckets.push((commits[from], &commit_secrets[from]));
        }

        let proof_system = crate::dleq::ProofSystem::default();
        let n_oracles = params.oracle_keys.len();
        let anticipated_attestations = (0..n_oracles)
            .map(|oracle_index| params.iter_anticipations(oracle_index).collect::<Vec<_>>())
            .collect::<Vec<_>>();

        let scalar_polys = (0..params.n_outcomes)
            .map(|outcome_index| {
                let secret = secrets[outcome_index as usize].clone();
                let mut poly = crate::poly::ScalarPoly::random(
                    (params.threshold - 1) as usize,
                    &mut rand::thread_rng(),
                );
                poly.push_front(secret);
                poly
            })
            .collect::<Vec<_>>();

        let bit_map: Vec<Vec<[ChainScalar; 2]>> = (0..n_oracles)
            .map(|_| {
                (0..params.n_outcome_bits())
                    .map(|_| {
                        [
                            ChainScalar::random(&mut rand::thread_rng()),
                            ChainScalar::random(&mut rand::thread_rng()),
                        ]
                    })
                    .collect()
            })
            .collect();

        let mut encryptions = vec![];

        for (oracle_index, bits_window) in buckets
            .chunks((params.n_outcome_bits() * 2 * params.bucket_size as u32) as usize)
            .enumerate()
        {
            for (outcome_bit_index, bit_window) in bits_window
                .chunks((2 * params.bucket_size) as usize)
                .enumerate()
            {
                for (bit_value_index, bit_value_window) in
                    bit_window.chunks(params.bucket_size as usize).enumerate()
                {
                    let t = &bit_map[oracle_index][outcome_bit_index][bit_value_index];
                    let anticipated_attestation =
                        anticipated_attestations[oracle_index][outcome_bit_index][bit_value_index];

                    for (commit, (ri, ri_prime, ri_mapped)) in bit_value_window {
                        // compute the ElGamal encryption of ri_mapped
                        let ri_encryption = anticipated_attestation * ri_prime + ri_mapped;
                        // create proof ElGamal encryption value is same as commitment
                        let proof = crate::dleq::prove_eqaulity(
                            &proof_system,
                            ri_prime.clone(),
                            ri_encryption,
                            anticipated_attestation,
                            params.elgamal_base,
                            commit.C,
                        );

                        // one-time pad of the secret_share in Z_q
                        let padded_secret = s!(ri + t).mark::<Public>();
                        encryptions.push((proof, ri_encryption, padded_secret));
                    }
                }
            }
        }

        let secret_share_pads_by_oracle = (0..n_oracles)
            .map(|oracle_index| {
                let secret_share_pads = compute_pads(&bit_map[oracle_index][..]);

                secret_share_pads
                    .into_iter()
                    .enumerate()
                    .take(params.n_outcomes as usize)
                    .map(|(outcome_index, pad)| {
                        let scalar_poly = &scalar_polys[outcome_index];
                        let secret_share = scalar_poly.eval((oracle_index + 1) as u32);

                        s!(pad + secret_share).mark::<Public>()
                    })
                    .collect()
            })
            .collect();

        let bit_map_images = bit_map
            .iter()
            .map(|oracle_bits| {
                oracle_bits
                    .iter()
                    .map(|oracle_bit| {
                        [
                            g!({ &oracle_bit[0] } * G).normalize(),
                            g!({ &oracle_bit[1] } * G).normalize(),
                        ]
                    })
                    .collect()
            })
            .collect();

        let polys = scalar_polys
            .into_iter()
            .map(|mut poly| {
                poly.pop_front();
                poly.to_point_poly()
            })
            .collect();

        Ok(Message3 {
            encryptions,
            openings,
            polys,
            bit_map_images,
            secret_share_pads_by_oracle,
        })
    }
}

fn compute_pads(pads: &[[ChainScalar; 2]]) -> Vec<ChainScalar<Secret, Zero>> {
    _compute_pads(pads.len() - 1, ChainScalar::zero(), pads)
}

fn _compute_pads(
    cur_bit: usize,
    acc: ChainScalar<Secret, Zero>,
    pads: &[[ChainScalar; 2]],
) -> Vec<ChainScalar<Secret, Zero>> {
    let zero = s!(acc + { &pads[cur_bit][0] });
    let one = s!(acc + { &pads[cur_bit][1] });

    if cur_bit == 0 {
        vec![zero, one]
    } else {
        let mut children = _compute_pads(cur_bit - 1, zero, pads);
        children.extend(_compute_pads(cur_bit - 1, one, pads));
        children
    }
}
