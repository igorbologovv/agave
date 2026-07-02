//! Replay a previously generated slot-based synthetic sigverify fixture through the
//! real sigverifier packet channel.

#![allow(clippy::arithmetic_side_effects)]

extern crate clap4 as clap;

#[path = "support/sigverify_fixture_common.rs"]
mod sigverify_fixture_common;

use {
    agave_bls_sigverify::{bls_sigverifier::PerSlotTiming, stats::SigVerifierStatsSnapshot},
    agave_votor_messages::{
        certificate::CertificateType, sig_verified_messages::SigVerifiedBatch,
        unverified_vote_message::DecodedWireConsensusMessage, vote::VoteType,
        wire::VersionedWireConsensusMessage,
    },
    clap::{Parser, ValueEnum},
    rand::{Rng, SeedableRng, rngs::StdRng},
    sigverify_fixture_common::{
        ExampleContext, StoredPacket, StoredPacketKind, StoredWorkload, fixture_max_slot,
        init_example_context,
    },
    solana_perf::packet::{Packet, PacketBatch, RecycledPacketBatch, packet_config},
    std::{
        fs::File,
        io::BufReader,
        path::Path,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        thread,
        time::{Duration, Instant},
    },
};

const SEND_BLOCK_WARN_US: u64 = 100;

// Shred version the fixture generator stamps into every payload/wire message
// (see FIXTURE_SHRED_VERSION in sigverify_fixture_build). Decoding the stored
// wire bytes to tally message types requires the same value.
const REPLAY_SHRED_VERSION: u16 = 0;

/// Per-`VoteType` counts, for comparing votes sent vs delivered.
#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct VoteTypeCounts {
    pub notarize: u64,
    pub notarize_fallback: u64,
    pub skip: u64,
    pub skip_fallback: u64,
    pub finalize: u64,
    pub genesis: u64,
}

impl VoteTypeCounts {
    fn add(&mut self, vote_type: VoteType) {
        self.add_n(vote_type, 1);
    }

    /// Add `n` votes of the same type at once. Verified votes are delivered as
    /// aggregates (one `VoteAggregate` per group covering many validators), so
    /// the drainer counts each aggregate's `num_votes()` to stay comparable with
    /// the per-vote sent tally.
    fn add_n(&mut self, vote_type: VoteType, n: u64) {
        match vote_type {
            VoteType::Notarize => self.notarize += n,
            VoteType::NotarizeFallback => self.notarize_fallback += n,
            VoteType::Skip => self.skip += n,
            VoteType::SkipFallback => self.skip_fallback += n,
            VoteType::Finalize => self.finalize += n,
            VoteType::Genesis => self.genesis += n,
        }
    }

    fn total(&self) -> u64 {
        self.notarize
            + self.notarize_fallback
            + self.skip
            + self.skip_fallback
            + self.finalize
            + self.genesis
    }
}

/// Per-`CertificateType` counts, for comparing certs sent vs delivered.
#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct CertTypeCounts {
    pub notarize: u64,
    pub notarize_fallback: u64,
    pub skip: u64,
    pub finalize: u64,
    pub finalize_fast: u64,
    pub genesis: u64,
}

impl CertTypeCounts {
    fn add(&mut self, cert_type: &CertificateType) {
        match cert_type {
            CertificateType::Notarize(_) => self.notarize += 1,
            CertificateType::NotarizeFallback(_) => self.notarize_fallback += 1,
            CertificateType::Skip(_) => self.skip += 1,
            CertificateType::Finalize(_) => self.finalize += 1,
            CertificateType::FinalizeFast(_) => self.finalize_fast += 1,
            CertificateType::Genesis(_) => self.genesis += 1,
        }
    }

    fn total(&self) -> u64 {
        self.notarize
            + self.notarize_fallback
            + self.skip
            + self.finalize
            + self.finalize_fast
            + self.genesis
    }
}

/// Decode every stored packet and tally the vote/cert types the workload sends
/// into the verifier. Returns (votes, certs, undecodable-packet count). Runs
/// once during prep, off the timed path.
fn tally_sent_types(workload: &StoredWorkload) -> (VoteTypeCounts, CertTypeCounts, u64) {
    let mut votes = VoteTypeCounts::default();
    let mut certs = CertTypeCounts::default();
    let mut undecodable = 0u64;

    for packet in &workload.packets {
        let Ok(msg) = VersionedWireConsensusMessage::deserialize_with_expected_shred_version(
            packet.message_bytes.as_slice(),
            packet_config(),
            REPLAY_SHRED_VERSION,
        ) else {
            undecodable += 1;
            continue;
        };

        match DecodedWireConsensusMessage::new(msg) {
            DecodedWireConsensusMessage::Vote(v) => votes.add(v.vote.get_type()),
            DecodedWireConsensusMessage::Certificate(c) => certs.add(&c.cert_type),
        }
    }

    (votes, certs, undecodable)
}

#[derive(Debug, Clone, Copy, ValueEnum, serde::Serialize)]
pub enum ReplayArrivalPattern {
    /// Use arrival_us from the fixture file as-is.
    Stored,

    /// Reassign votes and certs uniformly across each slot window.
    Uniform,

    /// Reassign votes uniformly, but place certs into random bursts.
    CertBursts,
}

#[derive(Parser)]
pub struct ReplayConfig {
    #[arg(long, help = "Emit CSV output instead of human-readable output")]
    pub csv: bool,

    #[arg(
        long = "input",
        help = "Path to a previously generated workload fixture"
    )]
    pub input: String,

    #[arg(
        long = "arrival-pattern",
        value_enum,
        default_value = "cert-bursts",
        help = "Replay arrival layout: stored, uniform, or cert-bursts"
    )]
    pub arrival_pattern: ReplayArrivalPattern,

    #[arg(
        long = "arrival-seed",
        default_value_t = 0,
        help = "Seed for replay-only arrival reshuffling; 0 derives it from workload.seed"
    )]
    pub arrival_seed: u64,

    #[arg(
        long = "cert-bursts-per-slot",
        default_value_t = 20,
        help = "Number of cert arrival bursts generated per slot for cert-bursts layout"
    )]
    pub cert_bursts_per_slot: usize,

    #[arg(
        long = "cert-burst-jitter-us",
        default_value_t = 500,
        help = "Maximum +/- jitter around each cert burst center in microseconds"
    )]
    pub cert_burst_jitter_us: u64,

    #[arg(
        long = "batch-window-us",
        default_value_t = 1600,
        help = "Time window in microseconds used to collect arrived packets into one PacketBatch"
    )]
    pub batch_window_us: u64,

    #[arg(
        long = "max-packets-per-batch",
        default_value_t = 1024,
        help = "Maximum number of packets emitted in one synthetic PacketBatch"
    )]
    pub max_packets_per_batch: usize,

    #[arg(
        long = "num-threads",
        help = "Thread count for the verifier thread pool"
    )]
    pub num_threads: usize,

    #[arg(
        long = "debug-batches",
        default_value_t = 0,
        help = "Print the first N timed batches before and during replay"
    )]
    pub debug_batches: usize,
}

#[derive(Debug, serde::Serialize)]
pub struct OutputRow {
    pub seed: u64,
    pub arrival_pattern: ReplayArrivalPattern,
    pub batch_window_us: u64,
    pub max_packets_per_batch: usize,
    pub emitted_batches: usize,
    pub avg_packets_per_batch: f64,
    pub num_slots: usize,
    pub votes_per_slot: usize,
    pub certs_per_slot: usize,
    pub base_slot: u64,
    pub slot_window_us: u64,
    pub cert_signers: usize,
    pub cert_ratio: f64,
    pub vote_ratio: f64,
    pub num_threads: usize,
    pub num_validators: usize,
    pub total_packets: usize,
    pub vote_packets: usize,
    pub cert_packets: usize,

    // Verifier busy-time attributed per emulated slot. Diagnostic only: this is
    // wall-clock of the single verifier thread and already reflects the
    // num_threads rayon pool, so it is NOT a thread-count estimate.
    pub verify_busy_total_us: u64,
    pub verify_busy_avg_us_per_slot: f64,
    pub verify_busy_max_us_per_slot: u64,
    pub verify_busy_max_slot: u64,

    // Realtime keep-up + latency metrics (see main() for how each is derived).
    pub verified_messages: u64,
    pub max_input_backlog: usize,
    pub completion_lag_us: u64,
    pub p50_latency_us: u64,
    pub p99_latency_us: u64,
    pub max_latency_us: u64,

    // Message accounting aggregates. Per-type breakdown and the verifier's own
    // drop counters are printed to stderr (nested structs don't serialize to
    // CSV). dropped = sent - delivered; the stderr block attributes the drops.
    pub sent_votes: u64,
    pub delivered_votes: u64,
    pub dropped_votes: u64,
    pub sent_certs: u64,
    pub delivered_certs: u64,
    pub dropped_certs: u64,
    pub undecodable_sent: u64,

    pub elapsed_us: u64,
}

pub struct TimedBatch {
    pub send_at_us: u64,
    pub batch: PacketBatch,
}

pub struct TimedBatchDebug {
    pub index: usize,
    pub send_at_us: u64,
    pub packet_count: usize,
    pub vote_count: usize,
    pub cert_count: usize,
    pub first_arrival_us: u64,
    pub last_arrival_us: u64,
}

fn validate_replay_config(config: &ReplayConfig) -> Result<(), String> {
    if config.batch_window_us == 0 {
        return Err("batch_window_us must be > 0".to_string());
    }

    if config.max_packets_per_batch == 0 {
        return Err("max_packets_per_batch must be > 0".to_string());
    }

    if config.num_threads == 0 {
        return Err("num_threads must be > 0".to_string());
    }

    if matches!(config.arrival_pattern, ReplayArrivalPattern::CertBursts)
        && config.cert_bursts_per_slot == 0
    {
        return Err("cert_bursts_per_slot must be > 0 for cert-bursts".to_string());
    }

    Ok(())
}

fn replay_arrival_seed(workload: &StoredWorkload, config: &ReplayConfig) -> u64 {
    if config.arrival_seed == 0 {
        workload.seed ^ 0xCE17_BAAD_D157_1B11
    } else {
        config.arrival_seed
    }
}

fn slot_rng_seed(seed: u64, slot_index: usize) -> u64 {
    seed ^ (slot_index as u64).wrapping_mul(0xA076_1D64_78BD_642F)
}

fn uniform_arrival_us(rng: &mut StdRng, slot_start_us: u64, slot_window_us: u64) -> u64 {
    slot_start_us + rng.random_range(0..slot_window_us)
}

fn burst_arrival_us(
    rng: &mut StdRng,
    slot_start_us: u64,
    slot_window_us: u64,
    burst_centers: &[u64],
    burst_jitter_us: u64,
) -> u64 {
    let center = burst_centers[rng.random_range(0..burst_centers.len())];

    let jitter_span = burst_jitter_us.saturating_mul(2).saturating_add(1);
    let jitter = rng.random_range(0..jitter_span) as i64 - burst_jitter_us as i64;

    let arrival_offset =
        (center as i64 + jitter).clamp(0, slot_window_us.saturating_sub(1) as i64) as u64;

    slot_start_us + arrival_offset
}

fn reshuffle_workload_for_replay(
    workload: &StoredWorkload,
    config: &ReplayConfig,
) -> StoredWorkload {
    if matches!(config.arrival_pattern, ReplayArrivalPattern::Stored) {
        return workload.clone();
    }

    let seed = replay_arrival_seed(workload, config);
    let mut packets = workload.packets.clone();

    let mut slot_rngs: Vec<StdRng> = (0..workload.num_slots)
        .map(|slot_index| StdRng::seed_from_u64(slot_rng_seed(seed, slot_index)))
        .collect();

    let cert_burst_centers_by_slot: Vec<Vec<u64>> = (0..workload.num_slots)
        .map(|slot_index| {
            let mut rng = StdRng::seed_from_u64(slot_rng_seed(seed ^ 0xC347_B015, slot_index));

            (0..config.cert_bursts_per_slot)
                .map(|_| rng.random_range(0..workload.slot_window_us))
                .collect()
        })
        .collect();

    for packet in packets.iter_mut() {
        let slot_index = packet.slot_index;
        let slot_start_us = slot_index as u64 * workload.slot_window_us;
        let rng = &mut slot_rngs[slot_index];

        packet.arrival_us = match config.arrival_pattern {
            ReplayArrivalPattern::Stored => packet.arrival_us,
            ReplayArrivalPattern::Uniform => {
                uniform_arrival_us(rng, slot_start_us, workload.slot_window_us)
            }
            ReplayArrivalPattern::CertBursts => match packet.kind {
                StoredPacketKind::Vote => {
                    uniform_arrival_us(rng, slot_start_us, workload.slot_window_us)
                }
                StoredPacketKind::Cert => burst_arrival_us(
                    rng,
                    slot_start_us,
                    workload.slot_window_us,
                    &cert_burst_centers_by_slot[slot_index],
                    config.cert_burst_jitter_us,
                ),
            },
        };
    }

    packets.sort_by_key(|packet| packet.arrival_us);

    StoredWorkload {
        seed: workload.seed,
        num_slots: workload.num_slots,
        votes_per_slot: workload.votes_per_slot,
        certs_per_slot: workload.certs_per_slot,
        base_slot: workload.base_slot,
        slot_window_us: workload.slot_window_us,
        cert_signers: workload.cert_signers,
        num_validators: workload.num_validators,
        total_packets: workload.total_packets,
        vote_packets: workload.vote_packets,
        cert_packets: workload.cert_packets,
        packets,
    }
}

fn stored_packet_to_packet(stored: StoredPacket) -> Packet {
    let mut packet = Packet::default();
    let data_len = stored.message_bytes.len();

    packet.buffer_mut()[..data_len].copy_from_slice(&stored.message_bytes);
    packet.meta_mut().size = data_len;
    packet.meta_mut().set_remote_pubkey(stored.remote_pubkey);

    packet
}

fn make_timed_batches(
    workload: &StoredWorkload,
    batch_window_us: u64,
    max_packets_per_batch: usize,
) -> Vec<TimedBatch> {
    assert!(batch_window_us > 0);
    assert!(max_packets_per_batch > 0);

    if workload.packets.is_empty() {
        return Vec::new();
    }

    let mut timed_batches = Vec::new();
    let mut packet_index = 0;

    while packet_index < workload.packets.len() {
        let first_packet_arrival_us = workload.packets[packet_index].arrival_us;
        let window_start_us = first_packet_arrival_us - (first_packet_arrival_us % batch_window_us);
        let window_end_us = window_start_us.saturating_add(batch_window_us);

        while packet_index < workload.packets.len()
            && workload.packets[packet_index].arrival_us < window_end_us
        {
            let mut packets = Vec::with_capacity(max_packets_per_batch);

            while packet_index < workload.packets.len()
                && workload.packets[packet_index].arrival_us < window_end_us
                && packets.len() < max_packets_per_batch
            {
                packets.push(stored_packet_to_packet(
                    workload.packets[packet_index].clone(),
                ));
                packet_index += 1;
            }

            if !packets.is_empty() {
                timed_batches.push(TimedBatch {
                    send_at_us: window_end_us,
                    batch: RecycledPacketBatch::new(packets).into(),
                });
            }
        }
    }

    timed_batches
}

fn debug_timed_batches(
    workload: &StoredWorkload,
    batch_window_us: u64,
    max_packets_per_batch: usize,
    max_batches: usize,
) -> Vec<TimedBatchDebug> {
    if max_batches == 0 || workload.packets.is_empty() {
        return Vec::new();
    }

    let mut result = Vec::new();
    let mut packet_index = 0;
    let mut batch_index = 0;

    while packet_index < workload.packets.len() && result.len() < max_batches {
        let first_packet_arrival_us = workload.packets[packet_index].arrival_us;
        let window_start_us = first_packet_arrival_us - (first_packet_arrival_us % batch_window_us);
        let window_end_us = window_start_us.saturating_add(batch_window_us);

        while packet_index < workload.packets.len()
            && workload.packets[packet_index].arrival_us < window_end_us
            && result.len() < max_batches
        {
            let first_arrival_us = workload.packets[packet_index].arrival_us;
            let mut last_arrival_us = first_arrival_us;
            let mut packet_count = 0usize;
            let mut vote_count = 0usize;
            let mut cert_count = 0usize;

            while packet_index < workload.packets.len()
                && workload.packets[packet_index].arrival_us < window_end_us
                && packet_count < max_packets_per_batch
            {
                match workload.packets[packet_index].kind {
                    StoredPacketKind::Vote => vote_count += 1,
                    StoredPacketKind::Cert => cert_count += 1,
                }

                packet_count += 1;
                last_arrival_us = workload.packets[packet_index].arrival_us;
                packet_index += 1;
            }

            if packet_count > 0 {
                result.push(TimedBatchDebug {
                    index: batch_index,
                    send_at_us: window_end_us,
                    packet_count,
                    vote_count,
                    cert_count,
                    first_arrival_us,
                    last_arrival_us,
                });

                batch_index += 1;
            }
        }
    }

    result
}

fn load_workload_from_file<P: AsRef<Path>>(
    path: P,
) -> Result<StoredWorkload, Box<dyn std::error::Error>> {
    let reader = BufReader::new(File::open(path)?);
    let workload = bincode::deserialize_from(reader)?;
    Ok(workload)
}

fn print_results(row: &OutputRow, csv_output: bool) {
    if csv_output {
        let mut writer = csv::WriterBuilder::new()
            .has_headers(false)
            .from_writer(std::io::stdout());

        writer.serialize(row).expect("failed to serialize CSV row");
        writer.flush().expect("failed to flush CSV writer");
    } else {
        println!("{row:#?}");
    }
}

/// Print the per-type sent-vs-delivered breakdown plus the verifier's own drop
/// counters to stderr. This is what confirms whether observed drops are legit:
/// `dropped = sent - delivered` for each type, and the verifier counters below
/// attribute those drops (e.g. `already_verified_dup` for duplicate cert types,
/// `old` for late arrivals).
fn print_message_accounting(
    sent_votes: &VoteTypeCounts,
    delivered_votes: &VoteTypeCounts,
    sent_certs: &CertTypeCounts,
    delivered_certs: &CertTypeCounts,
    undecodable_sent: u64,
    stats: &SigVerifierStatsSnapshot,
) {
    eprintln!("message accounting (sent -> delivered):");
    eprintln!(
        "  votes total: {} -> {} (dropped {})",
        sent_votes.total(),
        delivered_votes.total(),
        sent_votes.total().saturating_sub(delivered_votes.total()),
    );
    let vote_rows = [
        ("notarize", sent_votes.notarize, delivered_votes.notarize),
        (
            "notarize_fallback",
            sent_votes.notarize_fallback,
            delivered_votes.notarize_fallback,
        ),
        ("skip", sent_votes.skip, delivered_votes.skip),
        (
            "skip_fallback",
            sent_votes.skip_fallback,
            delivered_votes.skip_fallback,
        ),
        ("finalize", sent_votes.finalize, delivered_votes.finalize),
        ("genesis", sent_votes.genesis, delivered_votes.genesis),
    ];
    for (label, sent, delivered) in vote_rows {
        eprintln!("    {label:<18} {sent:>10} -> {delivered:>10}");
    }

    eprintln!(
        "  certs total: {} -> {} (dropped {})",
        sent_certs.total(),
        delivered_certs.total(),
        sent_certs.total().saturating_sub(delivered_certs.total()),
    );
    let cert_rows = [
        ("notarize", sent_certs.notarize, delivered_certs.notarize),
        (
            "notarize_fallback",
            sent_certs.notarize_fallback,
            delivered_certs.notarize_fallback,
        ),
        ("skip", sent_certs.skip, delivered_certs.skip),
        ("finalize", sent_certs.finalize, delivered_certs.finalize),
        (
            "finalize_fast",
            sent_certs.finalize_fast,
            delivered_certs.finalize_fast,
        ),
        ("genesis", sent_certs.genesis, delivered_certs.genesis),
    ];
    for (label, sent, delivered) in cert_rows {
        eprintln!("    {label:<18} {sent:>10} -> {delivered:>10}");
    }

    if undecodable_sent > 0 {
        eprintln!("  undecodable_sent: {undecodable_sent}");
    }

    eprintln!("  verifier counters:");
    eprintln!(
        "    packets: malformed={} discarded={}",
        stats.num_malformed_pkts, stats.num_discarded_pkts,
    );
    eprintln!(
        "    votes: to_verify={} optimistic_groups={} fallback_groups={} individual_verified={} \
         aggregates_sent={} banned={} old={} invalid_rank={} no_epoch_stakes={} too_far_future={}",
        stats.votes_to_sig_verify,
        stats.vote_groups_optimistic_verified,
        stats.vote_groups_fallback,
        stats.votes_individually_verified,
        stats.vote_aggregates_sent,
        stats.votes_banned,
        stats.num_old_votes_received,
        stats.discard_vote_invalid_rank,
        stats.discard_vote_no_epoch_stakes,
        stats.votes_too_far_in_future,
    );
    eprintln!(
        "    certs: to_verify={} sig_verified={} pool_sent={} old={} already_verified_dup={} \
         generated={} verify_failed={} too_far_future={} unnecessary_verified={}",
        stats.certs_to_sig_verify,
        stats.sig_verified_certs,
        stats.cert_pool_sent,
        stats.num_old_certs_received,
        stats.num_verified_certs_received,
        stats.num_generated_certs_received,
        stats.certificate_verification_failed,
        stats.certs_too_far_in_future,
        stats.unnecessary_certs_verified,
    );
}

/// Nearest-rank percentile of an already-sorted ascending slice, in the same
/// unit as the slice. Returns 0 for an empty slice.
fn percentile_us(sorted: &[u64], pct: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let last = sorted.len() - 1;
    let rank = (pct / 100.0 * last as f64).round() as usize;
    sorted[rank.min(last)]
}

fn wait_until(start: Instant, send_at_us: u64) {
    let target = start + Duration::from_micros(send_at_us);

    loop {
        let now = Instant::now();

        if now >= target {
            return;
        }

        let remaining = target.saturating_duration_since(now);

        if remaining > Duration::from_micros(100) {
            thread::sleep(remaining / 2);
        } else {
            std::hint::spin_loop();
        }
    }
}

fn elapsed_us_since(start: Instant) -> u64 {
    start.elapsed().as_micros() as u64
}

fn main() {
    let config = ReplayConfig::parse();

    validate_replay_config(&config).unwrap_or_else(|err| {
        eprintln!("error: {err}");
        std::process::exit(1);
    });

    let workload = load_workload_from_file(&config.input).unwrap_or_else(|err| {
        eprintln!("failed to load workload: {err}");
        std::process::exit(1);
    });

    let workload = reshuffle_workload_for_replay(&workload, &config);
    let timed_batches = make_timed_batches(
        &workload,
        config.batch_window_us,
        config.max_packets_per_batch,
    );

    let emitted_batches = timed_batches.len();
    let avg_packets_per_batch = if emitted_batches == 0 {
        0.0
    } else {
        workload.total_packets as f64 / emitted_batches as f64
    };

    let scheduled_end_us = timed_batches
        .last()
        .map(|timed_batch| timed_batch.send_at_us)
        .unwrap_or_default();

    if config.debug_batches > 0 {
        eprintln!(
            "debug: first {} timed batches after replay reshuffle:",
            config.debug_batches,
        );

        for batch in debug_timed_batches(
            &workload,
            config.batch_window_us,
            config.max_packets_per_batch,
            config.debug_batches,
        ) {
            eprintln!(
                "debug batch #{:04}: send_at_us={}, packets={}, votes={}, certs={}, \
                 first_arrival_us={}, last_arrival_us={}",
                batch.index,
                batch.send_at_us,
                batch.packet_count,
                batch.vote_count,
                batch.cert_count,
                batch.first_arrival_us,
                batch.last_arrival_us,
            );
        }
    }

    eprintln!(
        "Prepare phase is over; Start paced replay (arrival_pattern={:?}, emitted_batches={}, \
         avg_packets_per_batch={:.2}, scheduled_end_us={})",
        config.arrival_pattern, emitted_batches, avg_packets_per_batch, scheduled_end_us,
    );

    let max_slot = fixture_max_slot(workload.base_slot, workload.num_slots);
    let ctx = init_example_context(
        config.num_threads,
        workload.num_validators,
        workload.seed,
        workload.base_slot,
        max_slot,
    );

    let ExampleContext {
        verifier,
        packet_sender,
        validator_keypairs: _validator_keypairs,
        validator_ranks: _validator_ranks,
        _repair_receiver,
        _reward_receiver,
        _pool_receiver,
        _metrics_receiver,
    } = ctx;

    // Decode what we are about to send, by type, before the timed replay starts.
    let (sent_votes, sent_certs, undecodable_sent) = tally_sent_types(&workload);

    let exit = Arc::new(AtomicBool::new(false));
    let verifier_exit = Arc::clone(&exit);

    let timing = PerSlotTiming::new(workload.base_slot, workload.num_slots);

    // replay_start anchors both the send pacing and the pool drainer's output
    // timestamps so latency is measured against a single clock.
    let replay_start = Instant::now();

    let verifier_thread = thread::Builder::new()
        .name("sigverify-fixture-replay".to_string())
        .spawn(move || {
            let mut timing = timing;
            let stats = verifier.run_with_per_slot_timing(verifier_exit, &mut timing);
            (timing, stats)
        })
        .expect("failed to spawn verifier thread");

    // Drain the consensus-pool channel on its own thread, timestamping every
    // verified batch. This is mandatory, not just instrumentation: the pool
    // channel is bounded(1024) and `send_votes_to_pool`/`send_certs_to_pool`
    // fall back to a *blocking* send when it is full, so an undrained pool would
    // stall the verifier and destroy the timing we are measuring. The
    // repair/reward/metrics channels only ever use non-blocking try_send with
    // drop-on-full, so they never block the verifier; we keep their receivers
    // alive in scope only so their senders don't disconnect.
    let pool_drainer = thread::Builder::new()
        .name("sigverify-fixture-pool-drain".to_string())
        .spawn(move || {
            let mut events: Vec<(u64, u64)> = Vec::new();
            let mut cum_verified = 0u64;
            let mut delivered_votes = VoteTypeCounts::default();
            let mut delivered_certs = CertTypeCounts::default();
            while let Ok(batch) = _pool_receiver.recv() {
                match &batch {
                    SigVerifiedBatch::Votes(aggregates) => {
                        for aggregate in aggregates {
                            delivered_votes
                                .add_n(aggregate.vote().get_type(), aggregate.num_votes() as u64);
                        }
                    }
                    SigVerifiedBatch::Certificates(certs) => {
                        for cert in certs {
                            delivered_certs.add(&cert.cert_type);
                        }
                    }
                }
                cum_verified = cum_verified.saturating_add(batch.len() as u64);
                let t_out_us = replay_start.elapsed().as_micros() as u64;
                events.push((t_out_us, cum_verified));
            }
            (events, delivered_votes, delivered_certs)
        })
        .expect("failed to spawn pool drain thread");

    let mut max_schedule_lag_us = 0u64;
    let mut max_send_block_us = 0u64;
    let mut total_send_block_us = 0u64;
    let mut blocked_sends_over_100us = 0u64;
    let mut actual_send_end_us = 0u64;
    let mut max_input_backlog = 0usize;

    // (cumulative packets sent, wall-clock us when they entered the channel).
    // Monotonic in both columns, so a verified-message watermark maps back to
    // the send time of the batch that carried it.
    let mut sent_checkpoints: Vec<(u64, u64)> = Vec::with_capacity(emitted_batches);
    let mut cum_sent = 0u64;

    for (index, timed_batch) in timed_batches.into_iter().enumerate() {
        let batch_len = timed_batch.batch.len() as u64;

        wait_until(replay_start, timed_batch.send_at_us);

        let before_send_us = elapsed_us_since(replay_start);
        let schedule_lag_us = before_send_us.saturating_sub(timed_batch.send_at_us);

        let send_start = Instant::now();
        packet_sender
            .send(timed_batch.batch)
            .expect("packet receiver disconnected");
        let send_block_us = send_start.elapsed().as_micros() as u64;

        actual_send_end_us = elapsed_us_since(replay_start);
        cum_sent = cum_sent.saturating_add(batch_len);
        sent_checkpoints.push((cum_sent, before_send_us));

        max_input_backlog = max_input_backlog.max(packet_sender.len());
        max_schedule_lag_us = max_schedule_lag_us.max(schedule_lag_us);
        max_send_block_us = max_send_block_us.max(send_block_us);
        total_send_block_us = total_send_block_us.saturating_add(send_block_us);

        if send_block_us > SEND_BLOCK_WARN_US {
            blocked_sends_over_100us = blocked_sends_over_100us.saturating_add(1);
        }

        if index < config.debug_batches {
            eprintln!(
                "debug send #{:04}: scheduled_send_at_us={}, before_send_us={}, \
                 actual_send_end_us={}, schedule_lag_us={}, send_block_us={}",
                index,
                timed_batch.send_at_us,
                before_send_us,
                actual_send_end_us,
                schedule_lag_us,
                send_block_us,
            );
        }
    }

    // Let the verifier pull every buffered packet out of the channel before we
    // disconnect. recv_batches discards any batches still buffered at the moment
    // it observes a disconnect, so dropping the sender while the channel is
    // non-empty would silently lose the tail of the workload.
    while packet_sender.len() > 0 {
        thread::sleep(Duration::from_millis(1));
    }

    // Dropping the sender lets the (now-empty) channel disconnect, which ends
    // the verifier loop; that in turn drops the pool sender and ends the
    // drainer. exit is belt-and-suspenders in case disconnect is missed.
    drop(packet_sender);
    exit.store(true, Ordering::Relaxed);

    let (timing, verifier_stats) = verifier_thread
        .join()
        .expect("verifier thread panicked during replay");
    let (pool_events, delivered_votes, delivered_certs) = pool_drainer
        .join()
        .expect("pool drain thread panicked during replay");

    let timing_summary = timing.summary();
    let elapsed_us = elapsed_us_since(replay_start);

    eprintln!(
        "send schedule: scheduled_end_us={}, actual_send_end_us={}, send_lag_us={}, \
         max_schedule_lag_us={}, max_send_block_us={}, total_send_block_us={}, \
         blocked_sends_over_100us={}",
        scheduled_end_us,
        actual_send_end_us,
        actual_send_end_us.saturating_sub(scheduled_end_us),
        max_schedule_lag_us,
        max_send_block_us,
        total_send_block_us,
        blocked_sends_over_100us,
    );

    let cert_ratio = if workload.total_packets == 0 {
        0.0
    } else {
        workload.cert_packets as f64 / workload.total_packets as f64
    };

    let vote_ratio = if workload.total_packets == 0 {
        0.0
    } else {
        workload.vote_packets as f64 / workload.total_packets as f64
    };

    let verified_messages = pool_events.last().map(|(_, cum)| *cum).unwrap_or(0);

    // How far past the scheduled arrival of the last packet the verifier was
    // still emitting verified output. ~0 means it tracked real time; a large
    // value means it fell behind and is draining a backlog.
    let completion_lag_us = pool_events
        .last()
        .map(|(t_out_us, _)| t_out_us.saturating_sub(scheduled_end_us))
        .unwrap_or(0);

    // Order-based latency: map each verified-message watermark back to the send
    // time of the batch that carried that message. Approximate — the verifier
    // coalesces recv chunks (SOFT_RECEIVE_CAP) and splits votes/certs across two
    // rayon arms, so per-batch ordering is only roughly FIFO — but sound for the
    // p50/p99/max we report.
    let mut latencies_us: Vec<u64> = Vec::with_capacity(pool_events.len());
    for (t_out_us, cum_verified) in &pool_events {
        let idx = sent_checkpoints.partition_point(|&(cum, _)| cum < *cum_verified);
        let send_time_us = sent_checkpoints
            .get(idx)
            .or_else(|| sent_checkpoints.last())
            .map(|&(_, t)| t)
            .unwrap_or(0);
        latencies_us.push(t_out_us.saturating_sub(send_time_us));
    }
    latencies_us.sort_unstable();

    let p50_latency_us = percentile_us(&latencies_us, 50.0);
    let p99_latency_us = percentile_us(&latencies_us, 99.0);
    let max_latency_us = latencies_us.last().copied().unwrap_or(0);

    let sent_votes_total = sent_votes.total();
    let sent_certs_total = sent_certs.total();
    let delivered_votes_total = delivered_votes.total();
    let delivered_certs_total = delivered_certs.total();
    let dropped_votes = sent_votes_total.saturating_sub(delivered_votes_total);
    let dropped_certs = sent_certs_total.saturating_sub(delivered_certs_total);

    print_message_accounting(
        &sent_votes,
        &delivered_votes,
        &sent_certs,
        &delivered_certs,
        undecodable_sent,
        &verifier_stats,
    );

    let row = OutputRow {
        seed: workload.seed,
        arrival_pattern: config.arrival_pattern,
        batch_window_us: config.batch_window_us,
        max_packets_per_batch: config.max_packets_per_batch,
        emitted_batches,
        avg_packets_per_batch,
        num_slots: workload.num_slots,
        votes_per_slot: workload.votes_per_slot,
        certs_per_slot: workload.certs_per_slot,
        base_slot: workload.base_slot,
        slot_window_us: workload.slot_window_us,
        cert_signers: workload.cert_signers,
        cert_ratio,
        vote_ratio,
        num_threads: config.num_threads,
        num_validators: workload.num_validators,
        total_packets: workload.total_packets,
        vote_packets: workload.vote_packets,
        cert_packets: workload.cert_packets,

        verify_busy_total_us: timing_summary.total_us,
        verify_busy_avg_us_per_slot: timing_summary.avg_us_per_slot,
        verify_busy_max_us_per_slot: timing_summary.max_us_per_slot,
        verify_busy_max_slot: timing_summary.max_slot,

        verified_messages,
        max_input_backlog,
        completion_lag_us,
        p50_latency_us,
        p99_latency_us,
        max_latency_us,

        sent_votes: sent_votes_total,
        delivered_votes: delivered_votes_total,
        dropped_votes,
        sent_certs: sent_certs_total,
        delivered_certs: delivered_certs_total,
        dropped_certs,
        undecodable_sent,

        elapsed_us,
    };

    print_results(&row, config.csv);
}
