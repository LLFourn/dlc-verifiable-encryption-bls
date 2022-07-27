use crate::{common::Params, messages::*};
use anyhow::anyhow;
use bls12_381::{pairing as e, G1Affine, G1Projective, G2Affine, Gt};
use rand::{prelude::SliceRandom, RngCore};
use secp256kfun::{g, marker::*, s, Point, Scalar as ChainScalar, G};

pub struct Bob1 {
    commits: Vec<Commit>,
    message2: Message2,
}

impl Bob1 {
    pub fn new(message: Message1, params: &Params) -> anyhow::Result<(Bob1, Message2)> {
        if message.commits.len() != params.M() {
            return Err(anyhow!("Alice sent wrong number of commitments"));
        }
        let message2 = Self::gen_message2(&message.commits, params, &mut rand::thread_rng());
        Ok((
            Bob1 {
                commits: message.commits,
                message2: message2.clone(),
            },
            message2,
        ))
    }

    pub fn gen_message2(commits: &[Commit], params: &Params, rng: &mut impl RngCore) -> Message2 {
        let indexes = (0..commits.len()).collect::<Vec<_>>();
        let openings = indexes
            .choose_multiple(rng, params.num_openings())
            .cloned()
            .collect();

        let mut bucket_mapping = (0..params.NB()).collect::<Vec<_>>();
        bucket_mapping.shuffle(rng);

        Message2 {
            bucket_mapping,
            openings,
        }
    }

    pub fn receive_message(
        self,
        message: Message3,
        outcome_images: Vec<Point>,
        params: &Params,
    ) -> anyhow::Result<Bob2> {
        let Bob1 {
            mut commits,
            message2,
        } = self;
        let mut opened = vec![];
        let mut i = 0;

        commits.retain(|commit| {
            let open_it = message2.openings.contains(&i);
            if open_it {
                opened.push(commit.clone());
            }
            i += 1;
            !open_it
        });

        for (commit, opening) in opened.iter().zip(message.openings.iter()) {
            let ri_prime = opening;
            let Ri_prime = G1Affine::generator() * ri_prime;
            if Ri_prime != G1Projective::from(commit.C.0) {
                return Err(anyhow!("decommitment was wrong"));
            }
            let ri_mapped = commit.C.1 - params.elgamal_base * ri_prime;
            let ri = crate::common::map_Gt_to_Zq(&ri_mapped, commit.pad);

            if g!(ri * G) != commit.R {
                return Err(anyhow!(
                    "decommitment of chain scalar didn't match chain point"
                ));
            }
        }

        let mut buckets = Vec::with_capacity(params.NB());

        for (from, encryption) in message2.bucket_mapping.into_iter().zip(message.encryptions) {
            buckets.push((commits[from], encryption));
        }

        let proof_system = crate::dleq::ProofSystem::default();
        let n_oracles = params.oracle_keys.len();
        let anticipated_attestations = (0..n_oracles)
            .map(|oracle_index| params.iter_anticipations(oracle_index).collect::<Vec<_>>())
            .collect::<Vec<_>>();

        let mut bit_map_encryptions = vec![];

        for (oracle_index, bits_window) in buckets
            .chunks((params.n_outcome_bits() * 2 * params.bucket_size as u32) as usize)
            .enumerate()
        {
            let mut bits: Vec<[_; 2]> = vec![];
            for (bit_index, bit_window) in bits_window
                .chunks((2 * params.bucket_size) as usize)
                .enumerate()
            {
                let mut bit_values = vec![];
                for (bit_value_index, bit_value_window) in
                    bit_window.chunks((params.bucket_size) as usize).enumerate()
                {
                    let T = message.bit_map_images[oracle_index][bit_index][bit_value_index];
                    let anticipated_attestation =
                        anticipated_attestations[oracle_index][bit_index][bit_value_index];

                    let mut bit_value_bucket = vec![];

                    for (commit, (proof, encryption, padded_T)) in bit_value_window {
                        if !crate::dleq::verify_eqaulity(
                            &proof_system,
                            proof,
                            *encryption,
                            anticipated_attestation,
                            params.elgamal_base,
                            commit.C,
                        ) {
                            return Err(anyhow!(
                                "proof of equality between ciphertext and commitment was invalid"
                            ));
                        }

                        if g!(T + commit.R) != g!(padded_T * G) {
                            return Err(anyhow!("padded sig wasn't valid"));
                        }

                        bit_value_bucket.push(((commit.C.0, *encryption), *padded_T, commit.pad));
                    }

                    bit_values.push((bit_value_bucket, T))
                }
                bits.push(bit_values.try_into().unwrap());
            }
            bit_map_encryptions.push(bits);
        }

        for (oracle_index, secret_share_pads) in
            message.secret_share_pads_by_oracle.iter().enumerate()
        {
            let pad_images = compute_pad_images(&message.bit_map_images[oracle_index]);
            assert!(pad_images.len() >= params.n_outcomes as usize);
            assert_eq!(secret_share_pads.len(), params.n_outcomes as usize);
            for (outcome_index, (outcome_pad, expected_outcome_pad)) in
                secret_share_pads.iter().zip(pad_images).enumerate()
            {
                let mut poly = message.polys[outcome_index].clone();
                poly.push_front(outcome_images[outcome_index]);
                let secret_share_image = poly.eval((oracle_index + 1) as u32);
                if g!(outcome_pad * G) != g!(expected_outcome_pad + secret_share_image) {
                    return Err(anyhow!(
                        "outcome pad for outcome {} and oracle {} was wrong",
                        outcome_index,
                        oracle_index
                    ));
                }
            }
        }

        Ok(Bob2 {
            bit_map_encryptions,
            secret_share_pads_by_oracle: message.secret_share_pads_by_oracle,
            outcome_images,
        })
    }
}

pub struct Bob2 {
    // For every oracle
    bit_map_encryptions: Vec<
        // For every outcome bit
        Vec<
            // two bit values
            [(
                // a bucket of encryptions
                Vec<((G1Affine, Gt), ChainScalar<Public, Zero>, [u8; 32])>,
                // The image of the bit map that is encrypted
                Point,
            ); 2],
        >,
    >,
    // The image of the secret that should be revealed for each outcome
    secret_share_pads_by_oracle: Vec<Vec<ChainScalar<Public, Zero>>>,
    outcome_images: Vec<Point>,
}

impl Bob2 {
    pub fn receive_oracle_attestation(
        self,
        outcome_index: u32,
        attestations: Vec<Vec<G2Affine>>,
        params: &Params,
    ) -> anyhow::Result<ChainScalar<Public, Zero>> {
        let outcome_bits = crate::common::to_bits(outcome_index, params.n_outcome_bits() as usize);
        let mut secret_shares = vec![];
        for (oracle_index, bit_attestations) in attestations.into_iter().enumerate() {
            assert_eq!(
                outcome_bits.len(),
                bit_attestations.len(),
                "attestation for oracle didn't have the right number of signatures"
            );

            let bit_map_pads = outcome_bits
                .iter()
                .zip(bit_attestations)
                .enumerate()
                .map(|(bit_index, (bit_value, bit_attestation))| {
                    if !params.verify_bls_sig(
                        oracle_index,
                        bit_index as u32,
                        *bit_value,
                        bit_attestation,
                    ) {
                        eprintln!(
                            "BLS signature from oracle {} on bit {} was invalid",
                            oracle_index, bit_index
                        );
                        return None;
                    }
                    let (outcome_bit_bucket, expected_bit_map_image) =
                        &self.bit_map_encryptions[oracle_index][bit_index][*bit_value as usize];
                    outcome_bit_bucket.iter().find_map(
                        |(encryption, padded_bit_map_secret, pad)| {
                            let ri_mapped = encryption.1 - e(&encryption.0, &bit_attestation);
                            let ri = crate::common::map_Gt_to_Zq(&ri_mapped, *pad);
                            let bit_map_secret = s!(padded_bit_map_secret - ri).mark::<Public>();
                            let got_bit_map_image = g!(bit_map_secret * G);
                            if &got_bit_map_image == expected_bit_map_image {
                                Some(bit_map_secret)
                            } else {
                                eprintln!(
                                    "we didn't decrypt what was expected -- ignoring that share"
                                );
                                None
                            }
                        },
                    )
                })
                .collect::<Option<Vec<_>>>();

            let secret_share_pad = match bit_map_pads {
                Some(bit_map_pads) => bit_map_pads
                    .into_iter()
                    .fold(s!(0), |acc, pad| s!(acc + pad)),
                None => continue,
            };

            let secret_share =
                s!(
                    { self.secret_share_pads_by_oracle[oracle_index][outcome_index as usize] }
                        - secret_share_pad
                );

            secret_shares.push((
                ChainScalar::from(oracle_index as u32 + 1).expect_nonzero("added 1"),
                secret_share,
            ));
        }

        if secret_shares.len() >= params.threshold as usize {
            let shares = &secret_shares[0..params.threshold as usize];

            let secret = shares.iter().fold(s!(0), |acc, (x_j, y_j)| {
                let x_ms = shares
                    .iter()
                    .map(|(x_m, _)| x_m)
                    .filter(|x_m| x_m != &x_j)
                    .collect::<Vec<_>>();
                let (num, denom) = x_ms.iter().fold((s!(1), s!(1)), |(acc_n, acc_d), x_m| {
                    (
                        s!(acc_n * { x_m }),
                        s!(acc_d * ({ x_m } - x_j)).expect_nonzero("unreachable"),
                    )
                });
                let lagrange_coeff = s!(num * { denom.invert() });
                s!(acc + lagrange_coeff * y_j)
            });
            if g!(secret * G) != self.outcome_images[outcome_index as usize] {
                return Err(anyhow!("the secret we recovered was wrong"));
            }

            Ok(secret.mark::<Public>())
        } else {
            Err(anyhow!("not enough shares to reconstruct secret!"))
        }
    }
}

fn compute_pad_images(pads: &[[Point; 2]]) -> Vec<Point<Jacobian, Public, Zero>> {
    _compute_pad_images(pads.len() - 1, Point::zero().mark::<Jacobian>(), pads)
}

fn _compute_pad_images(
    cur_bit: usize,
    acc: Point<Jacobian, Public, Zero>,
    pads: &[[Point; 2]],
) -> Vec<Point<Jacobian, Public, Zero>> {
    let zero = g!(acc + { pads[cur_bit][0] });
    let one = g!(acc + { pads[cur_bit][1] });

    if cur_bit == 0 {
        vec![zero, one]
    } else {
        let mut children = _compute_pad_images(cur_bit - 1, zero, pads);
        children.extend(_compute_pad_images(cur_bit - 1, one, pads));
        children
    }
}
