use {
    super::{bls_sigverifier::BAN_TIMEOUT, errors::SigVerifyCertError, stats::SigVerifyCertStats},
    crate::bls_sigverify::{bls_sigverifier::NUM_SLOTS_FOR_VERIFY, utils::send_certs_to_pool},
    agave_bls_cert_verify::cert_verify::Error as BlsCertVerifyError,
    agave_votor_messages::{
        consensus_message::{Certificate, CertificateType, ConsensusMessage},
        fraction::Fraction,
    },
    crossbeam_channel::Sender,
    rayon::{
        ThreadPool,
        iter::{IntoParallelIterator, ParallelIterator},
    },
    solana_clock::Slot,
    solana_measure::measure::Measure,
    solana_pubkey::Pubkey,
    solana_runtime::bank::Bank,
    solana_streamer::nonblocking::simple_qos::SimpleQosBanlist,
    std::{collections::HashSet, num::NonZeroU64},
    thiserror::Error,
};

#[derive(Clone, Debug)]
pub(super) struct CertPayload {
    pub(super) cert: Certificate,
    pub(super) remote_pubkey: Pubkey,
}

#[derive(Debug, Error)]
enum CertVerifyError {
    #[error("Cert Verification Error {0}")]
    CertVerifyFailed(#[from] BlsCertVerifyError),
    #[error("Not enough stake {aggregate_stake}: {cert_fraction} < {required_fraction}")]
    NotEnoughStake {
        aggregate_stake: u64,
        cert_fraction: Fraction,
        required_fraction: Fraction,
    },
    #[error("discarding cert with slot {cert_slot} too far in future from root slot {root_slot}")]
    TooFarInFuture { cert_slot: Slot, root_slot: Slot },
}

/// Verifies certificates and sends the verified certificates to the consensus pool.
///
/// `seen_certs_set` is owned by the dedicated certificate worker. It is used as a
/// global certificate dedup cache before expensive BLS verification is scheduled.
///
/// Any certificate that fails verification has its [`CertificateType`] removed
/// from `seen_certs_set`, so a later packet can be retried.
pub(super) fn verify_and_send_certificates(
    seen_certs_set: &mut HashSet<CertificateType>,
    certs: Vec<CertPayload>,
    root_bank: &Bank,
    channel_to_pool: &Sender<Vec<ConsensusMessage>>,
    banlist: &SimpleQosBanlist,
    thread_pool: &ThreadPool,
) -> Result<SigVerifyCertStats, SigVerifyCertError> {
    let mut measure = Measure::start("verify_and_send_certificates");
    let mut stats = SigVerifyCertStats::default();

    if certs.is_empty() {
        return Ok(stats);
    }

    let mut certs_to_verify = Vec::with_capacity(certs.len());

    for cert_payload in certs {
        let cert_type = cert_payload.cert.cert_type;

        if !seen_certs_set.insert(cert_type) {
            stats.unnecessary_certs_verified += 1;
            continue;
        }

        certs_to_verify.push(cert_payload);
    }

    stats.certs_to_sig_verify += certs_to_verify.len() as u64;

    let messages = verify_certs(
        certs_to_verify,
        root_bank,
        seen_certs_set,
        &mut stats,
        banlist,
        thread_pool,
    );

    stats.sig_verified_certs += messages.len() as u64;

    send_certs_to_pool(messages, channel_to_pool, &mut stats)?;

    measure.stop();
    stats
        .fn_verify_and_send_certs_stats
        .add_sample(measure.as_us());

    Ok(stats)
}

/// Verifies certificates in `certs` and prepares them for forwarding.
///
/// The caller has already inserted each cert type into `seen_certs_set` before
/// calling this function. On verification failure, the cert type is removed from
/// `seen_certs_set`, allowing future retries.
fn verify_certs(
    certs: Vec<CertPayload>,
    root_bank: &Bank,
    _seen_certs_set: &mut HashSet<CertificateType>,
    stats: &mut SigVerifyCertStats,
    banlist: &SimpleQosBanlist,
    thread_pool: &ThreadPool,
) -> Vec<ConsensusMessage> {
    let verified = thread_pool.install(|| {
        certs
            .into_par_iter()
            .map(|cert_payload| {
                let res = verify_cert(&cert_payload.cert, root_bank);
                (cert_payload, res)
            })
            .collect::<Vec<_>>()
    });

    verified
        .into_iter()
        .filter_map(|(cert_payload, res)| match res {
            Ok(()) => Some(ConsensusMessage::Certificate(cert_payload.cert)),
            Err(e) => {
                match &e {
                    CertVerifyError::NotEnoughStake { .. }
                    | CertVerifyError::CertVerifyFailed(_) => {
                        if banlist.ban(cert_payload.remote_pubkey, BAN_TIMEOUT) {
                            stats.already_banned += 1;
                        } else {
                            info!(
                                "bls_cert_sigverify: banned sender={} due to error {e}",
                                cert_payload.remote_pubkey
                            );
                        }
                    }
                    CertVerifyError::TooFarInFuture { .. } => {}
                }

                match e {
                    CertVerifyError::NotEnoughStake { .. } => {
                        stats.stake_verification_failed += 1;
                    }
                    CertVerifyError::CertVerifyFailed(_) => {
                        stats.signature_verification_failed += 1;
                    }
                    CertVerifyError::TooFarInFuture { .. } => {
                        stats.too_far_in_future += 1;
                    }
                };

                None
            }
        })
        .collect()
}

fn verify_cert(cert: &Certificate, root_bank: &Bank) -> Result<(), CertVerifyError> {
    let cert_slot = cert.cert_type.slot();
    let root_slot = root_bank.slot();

    if cert_slot > root_slot.saturating_add(NUM_SLOTS_FOR_VERIFY) {
        return Err(CertVerifyError::TooFarInFuture {
            cert_slot,
            root_slot,
        });
    }

    let (aggregate_stake, total_stake) = root_bank.verify_certificate(cert)?;
    debug_assert!(aggregate_stake <= total_stake);

    verify_stake(cert, aggregate_stake, total_stake)
}

fn verify_stake(
    cert: &Certificate,
    aggregate_stake: u64,
    total_stake: u64,
) -> Result<(), CertVerifyError> {
    let (required_fraction, _) = cert.cert_type.limits_and_vote_types();
    let total_stake = NonZeroU64::new(total_stake).expect("Total stake cannot be zero");
    let cert_fraction = Fraction::new(aggregate_stake, total_stake);

    if cert_fraction >= required_fraction {
        Ok(())
    } else {
        Err(CertVerifyError::NotEnoughStake {
            aggregate_stake,
            cert_fraction,
            required_fraction,
        })
    }
}
