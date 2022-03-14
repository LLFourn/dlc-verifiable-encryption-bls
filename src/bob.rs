use crate::{
    common::{access_Zq, Params},
    dleq::{self, ProofSystem},
    messages::*,
};
use anyhow::anyhow;
use bls12_381::{pairing as e, G1Affine, G2Affine, G2Projective, Gt};
use rand::{prelude::SliceRandom, RngCore};
use schnorr_fun::fun::{g, marker::*, s, Point, Scalar as ChainScalar, G};

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
        anticipated_sigs: Vec<Point>,
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
            let Ri_prime = G2Affine::generator() * opening;
            if Ri_prime != G2Projective::from(commit.C.0) {
                return Err(anyhow!("decommitment was wrong"));
            }
            let ri_mapped = params.elgamal_base * opening - commit.C.1;
            let ri = access_Zq(&ri_mapped, commit.pad);

            if g!(ri * G) != commit.R {
                return Err(anyhow!(
                    "decommitment of chain scalar didn't match chain point"
                ));
            }
        }

        let mut buckets = vec![vec![]; params.n_outcomes];

        for (from, to) in message2.bucket_mapping.into_iter().enumerate() {
            let bucket_index = to / params.bucket_size;
            buckets[bucket_index].push((commits[from], &message.encryptions[from]));
        }

        let proof_system = ProofSystem::default();
        let mut encryption_buckets = vec![];
        for (i, bucket) in buckets.into_iter().enumerate() {
            let sig_point = params.anticipated_gt_event_index(&params.event_id, i);
            let mut encryption_bucket = vec![];
            let anticipated_sig = &anticipated_sigs[i];
            for (commit, (proof, encryption, padded_sig)) in bucket {
                if !dleq::verify_eqaulity(
                    &proof_system,
                    proof,
                    *encryption,
                    sig_point,
                    params.elgamal_base,
                    commit.C,
                ) {
                    return Err(anyhow!(
                        "proof for equality between ciphertext and commitment was invalid"
                    ));
                }

                if g!(anticipated_sig + commit.R) != g!(padded_sig * G) {
                    return Err(anyhow!("padded sig wasn't valid"));
                }

                encryption_bucket.push(((commit.C.0, *encryption), padded_sig.clone(), commit.pad));
            }
            encryption_buckets.push((encryption_bucket, *anticipated_sig));
        }

        Ok(Bob2 { encryption_buckets })
    }
}

pub struct Bob2 {
    encryption_buckets: Vec<(
        Vec<((G2Affine, Gt), ChainScalar<Secret, Zero>, [u8; 32])>,
        Point,
    )>,
}

impl Bob2 {
    pub fn receive_oracle_attestation(
        mut self,
        index: usize,
        attestation: G1Affine,
    ) -> anyhow::Result<ChainScalar<Secret, Zero>> {
        let bucket = self.encryption_buckets.remove(index);
        let anticipated_sig = &bucket.1;
        let sig = bucket.0.iter().find_map(|(encryption, padded_sig, pad)| {
            let ri_mapped = e(&attestation, &encryption.0) - &encryption.1;
            let ri = access_Zq(&ri_mapped, *pad);
            let sig = s!(padded_sig - ri);
            if &g!(sig * G) == anticipated_sig {
                Some(sig)
            } else {
                None
            }
        });

        sig.ok_or(anyhow!("all the ciphertexts were malicious!"))
    }
}
