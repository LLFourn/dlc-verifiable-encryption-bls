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
        mut message: Message3,
        sig_images: Vec<Point>,
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
        let mut anticipated_attestations = (0..n_oracles)
            .map(|oracle_index| params.iter_anticipations(oracle_index))
            .collect::<Vec<_>>();
        let mut outcome_buckets = vec![];

        for (outcome_index, buckets) in buckets
            .chunks(params.bucket_size as usize * n_oracles)
            .enumerate()
        {
            let secret_image = sig_images[outcome_index];
            let mut oracle_buckets = vec![];
            let poly = &mut message.polys[outcome_index];
            poly.push_front(secret_image);
            for (oracle_index, bucket) in buckets.chunks(params.bucket_size as usize).enumerate() {
                let anticipated_attestation =
                    anticipated_attestations[oracle_index].next().unwrap();
                let mut oracle_bucket = vec![];
                let sig_share_image = poly.eval((oracle_index + 1) as u32).normalize();
                for (commit, (proof, encryption, padded_sig)) in bucket {
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

                    if g!(sig_share_image + commit.R) != g!(padded_sig * G) {
                        return Err(anyhow!("padded sig wasn't valid"));
                    }

                    oracle_bucket.push(((commit.C.0, *encryption), padded_sig.clone(), commit.pad));
                }
                oracle_buckets.push((oracle_bucket, sig_share_image))
            }
            outcome_buckets.push((oracle_buckets, secret_image));
        }

        Ok(Bob2 { outcome_buckets })
    }
}

pub struct Bob2 {
    outcome_buckets: Vec<(
        // for every outcome:
        // 1. A list of entries corresponding to oracles
        Vec<(
            // For every oracle:
            // 1. A list of encryptions (all encrypting the same signature share)
            Vec<((G1Affine, Gt), ChainScalar<Secret, Zero>, [u8; 32])>,
            // 2. The image of the signature share that will be encrypted
            Point<Normal, Public, Zero>,
        )>,
        // 2. The sig image that should be unlocked iwth this outcome
        Point,
    )>,
}

impl Bob2 {
    pub fn receive_oracle_attestation(
        mut self,
        outcome_index: u32,
        attestations: Vec<G2Affine>,
        params: &Params,
    ) -> anyhow::Result<ChainScalar<Public, Zero>> {
        let (outcome_bucket, secret_image) = self.outcome_buckets.remove(outcome_index as usize);
        let mut secret_shares = vec![];
        for (oracle_index, ((oracle_bucket, secret_share_image), attestation)) in
            outcome_bucket.into_iter().zip(attestations).enumerate()
        {
            if !params.verify_bls_sig(oracle_index, outcome_index, attestation) {
                eprintln!("attestation didn't match anticipated attestation");
                continue;
            }

            for (encryption, padded_secret_share, pad) in oracle_bucket {
                let ri_mapped = encryption.1 - e(&encryption.0, &attestation);
                let ri = crate::common::map_Gt_to_Zq(&ri_mapped, pad);
                let secret_share = s!(padded_secret_share - ri).mark::<Public>();
                let got_secret_share_image = g!(secret_share * G);
                if got_secret_share_image == secret_share_image {
                    secret_shares.push((
                        ChainScalar::from(oracle_index as u32 + 1).expect_nonzero("added 1"),
                        secret_share,
                    ));
                    break;
                } else {
                    eprintln!(
                        "Found a malicious encryption. Expecting {:?} got {:?}",
                        secret_share_image, got_secret_share_image
                    );
                }
            }
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

            if g!(secret * G) != secret_image {
                return Err(anyhow!("the sig we recovered"));
            }

            Ok(secret.mark::<Public>())
        } else {
            Err(anyhow!("not enough shares to reconstruct secret!"))
        }
    }
}
