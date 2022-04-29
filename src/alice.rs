use crate::{common::map_Zq_to_Gt, common::Params, messages::*};
use anyhow::anyhow;
use bls12_381::{G2Affine, Gt, Scalar};
use ff::Field;
use secp256kfun::{g, s, Scalar as ChainScalar, G};

pub struct Alice1 {
    commit_secrets: Vec<(ChainScalar, Scalar, Gt)>,
    commits: Vec<Commit>,
}

impl Alice1 {
    pub fn new(params: &Params) -> (Alice1, Message1) {
        let (commits, commit_secrets): (Vec<Commit>, Vec<(ChainScalar, Scalar, Gt)>) = (0..params
            .M())
            .map(|_| {
                // hackily elements of Z_q to G_t
                let (hashed_xor_ri, ri, ri_mapped) = {
                    let ri = ChainScalar::random(&mut rand::thread_rng());
                    let (ri_mapped, pad) = map_Zq_to_Gt(&ri);
                    (pad, ri, ri_mapped)
                };

                let Ri = g!(ri * G).normalize();
                let ri_prime = Scalar::random(&mut rand::thread_rng());
                // Create Elgamal comitments in the form of (G_2, G_T)
                let C_i = (
                    // this is in G_2
                    (G2Affine::generator() * &ri_prime).into(),
                    // this is in G_T
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
        let mut anticipated_attestations = (0..n_oracles)
            .map(|oracle_index| params.iter_anticipations(oracle_index))
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

        let mut encryptions = vec![];

        for (outcome_index, buckets) in buckets
            .chunks(params.bucket_size as usize * n_oracles)
            .enumerate()
        {
            let scalar_poly = &scalar_polys[outcome_index];
            for (oracle_index, bucket) in buckets.chunks(params.bucket_size as usize).enumerate() {
                let anticipated_attestation =
                    anticipated_attestations[oracle_index].next().unwrap();
                let secret_share = scalar_poly.eval((oracle_index + 1) as u32);
                for (commit, (ri, ri_prime, ri_mapped)) in bucket {
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
                    let padded_secret = s!(ri + secret_share);
                    encryptions.push((proof, ri_encryption, padded_secret));
                }
            }
        }

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
        })
    }
}
