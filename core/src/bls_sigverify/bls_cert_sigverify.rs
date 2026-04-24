use {
    super::{bls_sigverifier::BAN_TIMEOUT, errors::SigVerifyCertError, stats::SigVerifyCertStats},
    crate::bls_sigverify::{bls_sigverifier::NUM_SLOTS_FOR_VERIFY, utils::send_certs_to_pool},
    agave_bls_cert_verify::cert_verify::Error as BlsCertVerifyError,
    agave_votor_messages::{
        consensus_message::{Certificate, CertificateType, ConsensusMessage},
        fraction::Fraction,
    },
    crossbeam_channel::Sender,
    solana_clock::Slot,
    solana_measure::measure::Measure,
    solana_pubkey::Pubkey,
    solana_runtime::bank::Bank,
    solana_streamer::nonblocking::simple_qos::SimpleQosBanlist,
    std::num::NonZeroU64,
    thiserror::Error,
};

#[derive(Clone, Debug)]
pub(super) struct CertPayload {
    pub(super) cert: Certificate,
    pub(super) remote_pubkey: Pubkey,
}

#[derive(Debug)]
pub(super) struct CertWorkerResult {
    pub(super) stats: SigVerifyCertStats,
    pub(super) newly_verified: Vec<CertificateType>,
}

#[derive(Debug, Error)]
enum CertVerifyError {
    #[error("certificate verification error: {0}")]
    CertVerifyFailed(#[from] BlsCertVerifyError),

    #[error("not enough stake {aggregate_stake}: {cert_fraction} < {required_fraction}")]
    NotEnoughStake {
        aggregate_stake: u64,
        cert_fraction: Fraction,
        required_fraction: Fraction,
    },

    #[error("discarding cert with slot {cert_slot} too far in future from root slot {root_slot}")]
    TooFarInFuture { cert_slot: Slot, root_slot: Slot },
}

/// Verifies certificates serially and sends valid certificates to the consensus pool.
///
/// This function is stateless with respect to the caller's verified-certificate cache:
/// it returns the successfully verified certificate types so the caller can update
/// its own state outside of the cert worker thread.
///
/// Invalid certificate senders are banlisted.
pub(super) fn verify_and_send_certificates(
    certs: Vec<CertPayload>,
    root_bank: &Bank,
    channel_to_pool: &Sender<Vec<ConsensusMessage>>,
    banlist: &SimpleQosBanlist,
) -> Result<CertWorkerResult, SigVerifyCertError> {
    let mut measure = Measure::start("verify_and_send_certificates_stateless_serial");
    let mut stats = SigVerifyCertStats::default();

    if certs.is_empty() {
        return Ok(CertWorkerResult {
            stats,
            newly_verified: Vec::new(),
        });
    }

    stats.certs_to_sig_verify += certs.len() as u64;

    let (messages, newly_verified) = verify_certs(certs, root_bank, &mut stats, banlist);

    stats.sig_verified_certs += messages.len() as u64;
    send_certs_to_pool(messages, channel_to_pool, &mut stats)?;

    measure.stop();
    stats
        .fn_verify_and_send_certs_stats
        .add_sample(measure.as_us());

    Ok(CertWorkerResult {
        stats,
        newly_verified,
    })
}

/// Verifies certificates serially and prepares valid messages for forwarding.
///
/// Returns:
/// - the valid certificate messages to forward to the consensus pool
/// - the verified certificate types so the caller can update its cache
///
/// Invalid certificate senders are banlisted.
fn verify_certs(
    certs: Vec<CertPayload>,
    root_bank: &Bank,
    stats: &mut SigVerifyCertStats,
    banlist: &SimpleQosBanlist,
) -> (Vec<ConsensusMessage>, Vec<CertificateType>) {
    let mut messages = Vec::new();
    let mut newly_verified = Vec::new();

    for cert_payload in certs {
        let CertPayload {
            cert,
            remote_pubkey,
        } = cert_payload;

        match verify_cert(&cert, root_bank) {
            Ok(()) => {
                newly_verified.push(cert.cert_type);
                messages.push(ConsensusMessage::Certificate(cert));
            }
            Err(err) => {
                if banlist.ban(remote_pubkey, BAN_TIMEOUT) {
                    stats.already_banned += 1;
                }

                match err {
                    CertVerifyError::NotEnoughStake { .. } => {
                        stats.stake_verification_failed += 1;
                    }
                    CertVerifyError::CertVerifyFailed(_) => {
                        stats.signature_verification_failed += 1;
                    }
                    CertVerifyError::TooFarInFuture { .. } => {
                        stats.too_far_in_future += 1;
                    }
                }
            }
        }
    }

    (messages, newly_verified)
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
    let total_stake = NonZeroU64::new(total_stake).expect("total stake cannot be zero");
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
