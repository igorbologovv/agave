use {
    crate::{
        bls_sigverifier::{BAN_TIMEOUT, NUM_SLOTS_FOR_VERIFY},
        errors::SigVerifyCertError,
        sig_verified_messages::SigVerifiedBatch,
        stats::SigVerifyCertStats,
        utils::send_certs_to_pool,
    },
    agave_bls_cert_verify::cert_verify::Error as BlsCertVerifyError,
    agave_votor_messages::{
        certificate::{Certificate, CertificateType},
        unverified_vote_message::UnverifiedCertificate,
    },
    crossbeam_channel::Sender,
    log::info,
    rayon::{
        ThreadPool,
        iter::{IntoParallelIterator, ParallelIterator},
    },
    solana_clock::Slot,
    solana_measure::measure::Measure,
    solana_pubkey::Pubkey,
    solana_runtime::bank::Bank,
    solana_streamer::nonblocking::simple_qos::SimpleQosBanlist,
    std::collections::HashSet,
    thiserror::Error,
};

pub(super) struct CertPayload {
    pub(super) cert: UnverifiedCertificate,
    pub(super) sender_identity_pubkey: Pubkey,
}

#[derive(Debug, Error)]
enum CertVerifyError {
    #[error("Cert Verification Error {0}")]
    CertVerifyFailed(#[from] BlsCertVerifyError),
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
    channel_to_pool: &Sender<SigVerifiedBatch>,
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
            stats.duplicate_certs_skipped_before_verify += 1;
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
    seen_certs_set: &mut HashSet<CertificateType>,
    stats: &mut SigVerifyCertStats,
    banlist: &SimpleQosBanlist,
    thread_pool: &ThreadPool,
) -> SigVerifiedBatch {
    let verified = thread_pool.install(|| {
        certs
            .into_par_iter()
            .map(|cert_payload| {
                let cert_type = cert_payload.cert.cert_type;
                let res = verify_cert(cert_payload.cert, root_bank);
                (res, cert_type, cert_payload.sender_identity_pubkey)
            })
            .collect::<Vec<_>>()
    });

    let certs = verified
        .into_iter()
        .filter_map(|(res, cert_type, sender_identity_pubkey)| match res {
            Ok(cert) => Some(cert),
            Err(e) => {
                seen_certs_set.remove(&cert_type);

                match &e {
                    CertVerifyError::CertVerifyFailed(_) => {
                        if banlist.ban(sender_identity_pubkey, BAN_TIMEOUT) {
                            stats.already_banned += 1;
                        } else {
                            info!(
                                "bls_cert_sigverify: banned sender={sender_identity_pubkey} due \
                                 to error {e}"
                            );
                        }
                    }
                    CertVerifyError::TooFarInFuture { .. } => {}
                }

                match e {
                    CertVerifyError::CertVerifyFailed(_) => {
                        stats.certificate_verification_failed += 1;
                    }
                    CertVerifyError::TooFarInFuture { .. } => {
                        stats.too_far_in_future += 1;
                    }
                };

                None
            }
        })
        .collect();

    SigVerifiedBatch::Certificates(certs)
}

fn verify_cert(
    cert: UnverifiedCertificate,
    root_bank: &Bank,
) -> Result<Certificate, CertVerifyError> {
    let cert_slot = cert.cert_type.slot();
    let root_slot = root_bank.slot();

    if cert_slot > root_slot.saturating_add(NUM_SLOTS_FOR_VERIFY) {
        return Err(CertVerifyError::TooFarInFuture {
            cert_slot,
            root_slot,
        });
    }

    let cert = root_bank.verify_certificate(cert)?;
    Ok(cert)
}
