use crate::{common::map_access_GT_to_Zq, common::Params, messages::*};
use anyhow::anyhow;
use bls12_381::{G2Affine, Gt, Scalar};
use ff::Field;
use group::Group;
use schnorr_fun::fun::{g, s, Scalar as ChainScalar, G};

pub struct Alice1 {
    secrets: Vec<(ChainScalar, Scalar, Gt)>,
    commits: Vec<Commit>,
}

pub struct Alice2 {}

impl Alice1 {
    pub fn new(params: &Params) -> (Alice1, Message1) {
        let (commits, secrets): (Vec<Commit>, Vec<(ChainScalar, Scalar, Gt)>) = (0..params.M())
            .map(|_| {
                // hackily elements of Z_q to G_t
                let (hashed_xor_ri, ri, ri_mapped) = {
                    let ri = ChainScalar::random(&mut rand::thread_rng());
                    let ri_mapped = sample_gt();
                    let pad = map_access_GT_to_Zq(&ri_mapped, &ri);
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
                secrets,
                commits: commits.clone(),
            },
            Message1 { commits },
        )
    }

    pub fn receive_message(
        self,
        message: Message2,
        secret_sigs: Vec<ChainScalar>,
        params: &Params,
    ) -> anyhow::Result<(Alice2, Message3)> {
        assert_eq!(secret_sigs.len(), params.n_outcomes);
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
            mut secrets,
            mut commits,
        } = self;
        let mut opened = vec![];
        let mut i = 0;

        commits.retain(|commit| {
            let open_it = message.openings.contains(&i);
            if open_it {
                opened.push(commit.clone());
            }
            i += 1;
            !open_it
        });
        let mut i = 0;
        let mut openings = vec![];
        secrets.retain(|secret| {
            let open_it = message.openings.contains(&i);
            if open_it {
                openings.push(secret.1);
            }
            i += 1;
            !open_it
        });

        let mut buckets = vec![vec![]; params.n_outcomes];
        for (from, to) in message.bucket_mapping.into_iter().enumerate() {
            let bucket_index = to / params.bucket_size;
            buckets[bucket_index].push((commits[from], &secrets[from]));
        }

        let proof_system = crate::dleq::ProofSystem::default();

        let encryptions = buckets
            .into_iter()
            .enumerate()
            .flat_map(|(i, bucket)| {
                let sig_point = params.anticipated_gt_event_index(&params.event_id, i);
                let secret_sig = &secret_sigs[i];
                let mut encryption_bucket = vec![];
                for (commit, (ri, ri_prime, ri_mapped)) in bucket {
                    // compute the ElGamal encryption to the signature of ri_mapped
                    let ri_encryption = sig_point * ri_prime + ri_mapped;
                    // create proof ElGamal encryption value is same as commitment
                    let proof = crate::dleq::prove_eqaulity(
                        &proof_system,
                        *ri_prime,
                        ri_encryption,
                        sig_point,
                        params.elgamal_base,
                        commit.C,
                    );
                    // one-time pad of the signature in Z_q
                    let padded_secret = s!(ri + secret_sig);
                    encryption_bucket.push((proof, ri_encryption, padded_secret));
                }
                encryption_bucket.into_iter()
            })
            .collect();

        Ok((
            Alice2 {},
            Message3 {
                encryptions,
                openings,
            },
        ))
    }
}

fn sample_gt() -> Gt {
    let scalar = Scalar::random(&mut rand::thread_rng());
    &Gt::generator() * &scalar
}
