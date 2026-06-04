//! Replay benchmark metrics and human-readable reporting.
//!
//! This module intentionally lives under `examples/support` because it is harness/reporting code,
//! not part of the production BLS sigverify pipeline.

use {
    crate::sigverify_fixture_common::{OutputRow, StoredWorkload, debug_timed_batches},
    agave_votor_messages::consensus_message::ConsensusMessage,
    solana_clock::Slot,
    solana_core::bls_sigverify::bls_sigverifier::VerifyBatchSummary,
    solana_streamer::packet::PacketBatch,
    std::{
        collections::VecDeque,
        fmt::{self, Display, Formatter},
        sync::{
            Mutex,
            atomic::{AtomicU64, Ordering},
        },
        time::Instant,
    },
};

const SEND_BLOCK_WARN_US: u64 = 100;

fn us_to_ms(us: u64) -> f64 {
    us as f64 / 1000.0
}

fn avg_u64(total: u64, count: u64) -> f64 {
    if count == 0 {
        0.0
    } else {
        total as f64 / count as f64
    }
}

pub fn count_votes_in_batch(batch: &PacketBatch) -> usize {
    batch
        .iter()
        .filter(|packet| {
            if packet.meta().discard() {
                return false;
            }

            matches!(
                packet.deserialize_slice::<ConsensusMessage, _>(..),
                Ok(ConsensusMessage::Vote(_))
            )
        })
        .count()
}

#[derive(Debug)]
struct PendingVoteBatchLatency {
    batch_seq: u64,
    vote_count: usize,
    start: Instant,
}

#[derive(Debug)]
struct CompletedVoteBatchLatency {
    batch_seq: u64,
    vote_count: usize,
    start: Instant,
    done: Instant,
}

#[derive(Debug, Default, Clone)]
struct VoteBatchLatencySummary {
    completed_batches: usize,
    pending_batches: usize,
    vote_count: u64,
    missing_done_events: u64,

    total_batch_latency_us: u64,
    avg_batch_latency_ms: f64,
    amortized_send_to_done_ms_per_vote: f64,
    vote_weighted_avg_latency_ms: f64,

    p50_us: u64,
    p95_us: u64,
    p99_us: u64,
    max_us: u64,
    max_batch_seq: u64,
}

impl Display for VoteBatchLatencySummary {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== Send-to-vote-done timing ===")?;
        writeln!(f, "Main result")?;
        writeln!(
            f,
            "  send_to_done cost:            {:.6} ms/vote",
            self.amortized_send_to_done_ms_per_vote
        )?;
        writeln!(
            f,
            "  formula:                      sum(PacketBatch send->done latency) / votes"
        )?;

        writeln!(f, "PacketBatch timing")?;
        writeln!(
            f,
            "  completed PacketBatches:      {}",
            self.completed_batches
        )?;
        writeln!(f, "  completed votes:              {}", self.vote_count)?;
        writeln!(
            f,
            "  total PacketBatch latency:    {:.3} ms",
            us_to_ms(self.total_batch_latency_us)
        )?;
        writeln!(
            f,
            "  avg PacketBatch latency:      {:.3} ms",
            self.avg_batch_latency_ms
        )?;
        writeln!(
            f,
            "  vote-weighted avg latency:    {:.3} ms",
            self.vote_weighted_avg_latency_ms
        )?;
        writeln!(
            f,
            "  p50 / p95 / p99 latency:      {:.3} / {:.3} / {:.3} ms",
            us_to_ms(self.p50_us),
            us_to_ms(self.p95_us),
            us_to_ms(self.p99_us),
        )?;
        writeln!(
            f,
            "  max PacketBatch latency:      {:.3} ms (batch {})",
            us_to_ms(self.max_us),
            self.max_batch_seq,
        )?;

        writeln!(f, "Sanity")?;
        writeln!(
            f,
            "  pending PacketBatches:        {}",
            self.pending_batches
        )?;
        writeln!(
            f,
            "  missing done events:          {}",
            self.missing_done_events
        )?;

        Ok(())
    }
}

#[derive(Debug, Default)]
struct VoteBatchLatencyTracker {
    pending: Mutex<VecDeque<PendingVoteBatchLatency>>,
    completed: Mutex<Vec<CompletedVoteBatchLatency>>,
    missing_done_events: AtomicU64,
}

impl VoteBatchLatencyTracker {
    fn push_pending_batch(&self, batch_seq: u64, vote_count: usize, start: Instant) {
        self.pending
            .lock()
            .unwrap()
            .push_back(PendingVoteBatchLatency {
                batch_seq,
                vote_count,
                start,
            });
    }

    fn mark_next_batches_done(&self, batch_count: usize, done: Instant) {
        for _ in 0..batch_count {
            let pending = self.pending.lock().unwrap().pop_front();

            let Some(pending) = pending else {
                self.missing_done_events.fetch_add(1, Ordering::Relaxed);
                continue;
            };

            if pending.vote_count == 0 {
                continue;
            }

            self.completed
                .lock()
                .unwrap()
                .push(CompletedVoteBatchLatency {
                    batch_seq: pending.batch_seq,
                    vote_count: pending.vote_count,
                    start: pending.start,
                    done,
                });
        }
    }

    fn summary(&self) -> VoteBatchLatencySummary {
        let pending_batches = self.pending.lock().unwrap().len();
        let completed = self.completed.lock().unwrap();

        let completed_batches = completed.len();

        let mut weighted_latencies: Vec<(u64, u64, u64)> = completed
            .iter()
            .map(|batch| {
                let latency_us = batch.done.duration_since(batch.start).as_micros() as u64;
                let vote_count = batch.vote_count as u64;

                (latency_us, vote_count, batch.batch_seq)
            })
            .collect();

        weighted_latencies.sort_by_key(|(latency_us, _, _)| *latency_us);

        let vote_count: u64 = weighted_latencies
            .iter()
            .map(|(_, vote_count, _)| *vote_count)
            .sum();

        if vote_count == 0 {
            return VoteBatchLatencySummary {
                completed_batches,
                pending_batches,
                missing_done_events: self.missing_done_events.load(Ordering::Relaxed),
                ..VoteBatchLatencySummary::default()
            };
        }

        let total_batch_latency_us = weighted_latencies
            .iter()
            .fold(0u64, |sum, (latency_us, _, _)| {
                sum.saturating_add(*latency_us)
            });

        let avg_batch_latency_ms =
            total_batch_latency_us as f64 / completed_batches as f64 / 1000.0;

        let amortized_send_to_done_ms_per_vote =
            total_batch_latency_us as f64 / vote_count as f64 / 1000.0;

        let weighted_sum: u128 = weighted_latencies
            .iter()
            .map(|(latency_us, vote_count, _)| *latency_us as u128 * *vote_count as u128)
            .sum();

        let vote_weighted_avg_latency_ms = weighted_sum as f64 / vote_count as f64 / 1000.0;

        let p50_us = weighted_percentile_us(&weighted_latencies, vote_count, 0.50);
        let p95_us = weighted_percentile_us(&weighted_latencies, vote_count, 0.95);
        let p99_us = weighted_percentile_us(&weighted_latencies, vote_count, 0.99);

        let (max_us, _, max_batch_seq) = weighted_latencies
            .iter()
            .max_by_key(|(latency_us, _, _)| *latency_us)
            .copied()
            .unwrap_or_default();

        VoteBatchLatencySummary {
            completed_batches,
            pending_batches,
            vote_count,
            missing_done_events: self.missing_done_events.load(Ordering::Relaxed),
            total_batch_latency_us,
            avg_batch_latency_ms,
            amortized_send_to_done_ms_per_vote,
            vote_weighted_avg_latency_ms,
            p50_us,
            p95_us,
            p99_us,
            max_us,
            max_batch_seq,
        }
    }
}

fn weighted_percentile_us(entries: &[(u64, u64, u64)], total_weight: u64, percentile: f64) -> u64 {
    if entries.is_empty() || total_weight == 0 {
        return 0;
    }

    let target = ((total_weight as f64) * percentile).ceil() as u64;
    let mut cumulative = 0u64;

    for (latency_us, weight, _) in entries {
        cumulative = cumulative.saturating_add(*weight);

        if cumulative >= target {
            return *latency_us;
        }
    }

    entries
        .last()
        .map(|(latency_us, _, _)| *latency_us)
        .unwrap_or(0)
}

#[derive(Debug)]
struct PerSlotTiming {
    base_slot: Slot,
    per_slot_us: Vec<u64>,
}

#[derive(Debug, Clone, Copy, Default)]
struct PerSlotTimingSummary {
    total_us: u64,
    avg_us_per_slot: f64,
    max_us_per_slot: u64,
    max_slot: Slot,
}

impl PerSlotTiming {
    fn new(base_slot: Slot, num_slots: usize) -> Self {
        Self {
            base_slot,
            per_slot_us: vec![0; num_slots],
        }
    }

    fn record(&mut self, summary: &VerifyBatchSummary) {
        #[cfg(feature = "dev-context-only-utils")]
        {
            let total_messages: u64 = summary
                .slot_message_counts
                .iter()
                .map(|(_, count)| *count)
                .sum();

            if total_messages == 0 || summary.module_us == 0 {
                return;
            }

            let mut assigned_us = 0u64;
            let mut first_nonzero_index = None;

            for (slot, count) in &summary.slot_message_counts {
                let Some(offset) = slot.checked_sub(self.base_slot) else {
                    continue;
                };

                let index = offset as usize;

                let Some(slot_us_total) = self.per_slot_us.get_mut(index) else {
                    continue;
                };

                if *count == 0 {
                    continue;
                }

                if first_nonzero_index.is_none() {
                    first_nonzero_index = Some(index);
                }

                let slot_us =
                    ((summary.module_us as u128 * *count as u128) / total_messages as u128) as u64;

                *slot_us_total = slot_us_total.saturating_add(slot_us);
                assigned_us = assigned_us.saturating_add(slot_us);
            }

            if let Some(index) = first_nonzero_index {
                let remainder_us = summary.module_us.saturating_sub(assigned_us);

                if let Some(slot_us_total) = self.per_slot_us.get_mut(index) {
                    *slot_us_total = slot_us_total.saturating_add(remainder_us);
                }
            }
        }

        #[cfg(not(feature = "dev-context-only-utils"))]
        {
            let _ = summary;
        }
    }

    fn summary(&self) -> PerSlotTimingSummary {
        if self.per_slot_us.is_empty() {
            return PerSlotTimingSummary::default();
        }

        let total_us: u64 = self.per_slot_us.iter().sum();

        let (max_index, max_us_per_slot) = self
            .per_slot_us
            .iter()
            .copied()
            .enumerate()
            .max_by_key(|(_, value)| *value)
            .unwrap_or((0, 0));

        PerSlotTimingSummary {
            total_us,
            avg_us_per_slot: total_us as f64 / self.per_slot_us.len() as f64,
            max_us_per_slot,
            max_slot: self.base_slot + max_index as Slot,
        }
    }
}

#[derive(Debug, Default)]
struct AggregatedVerifySummary {
    jobs: u64,

    received_batches: u64,
    non_empty_batches: u64,
    input_packets: u64,

    batches_with_kept_votes: u64,
    batches_with_kept_certs: u64,
    batches_with_kept_votes_and_certs: u64,

    raw_vote_messages: u64,
    raw_cert_messages: u64,

    votes_to_verify: u64,
    certs_to_verify: u64,
    certs_sent_to_sigverify: u64,
    certs_skipped_seen: u64,

    discarded_packets: u64,
    malformed_packets: u64,
    missing_remote_pubkey: u64,
    old_certs: u64,
    generated_certs: u64,

    extract_filter_us: u64,
    cert_worker_send_us: u64,
    vote_path_us: u64,
    cert_reply_wait_us: u64,
    module_us: u64,

    sig_verified_votes: u64,
    vote_signature_failed: u64,
    vote_too_far_future: u64,

    cert_sig_verified: u64,
    cert_signature_failed: u64,
    cert_stake_failed: u64,
    cert_too_far_future: u64,
    cert_duplicates_skipped_before_verify: u64,

    configured_vote_threads: usize,

    max_received_batches: usize,
    max_received_batches_job: u64,

    max_packets_in_batch: usize,
    max_packets_in_batch_job: u64,

    max_input_packets: u64,
    max_input_packets_job: u64,

    max_votes_to_verify: u64,
    max_votes_to_verify_job: u64,

    max_certs_to_verify: u64,
    max_certs_to_verify_job: u64,

    max_vote_path_us: u64,
    max_vote_path_job: u64,

    max_cert_reply_wait_us: u64,
    max_cert_reply_wait_job: u64,

    max_module_us: u64,
    max_module_job: u64,
}

impl AggregatedVerifySummary {
    fn record(&mut self, summary: &VerifyBatchSummary) {
        self.jobs = self.jobs.saturating_add(1);
        let job_id = self.jobs;

        self.received_batches = self
            .received_batches
            .saturating_add(summary.received_batches as u64);
        self.non_empty_batches = self
            .non_empty_batches
            .saturating_add(summary.non_empty_batches as u64);
        self.input_packets = self.input_packets.saturating_add(summary.input_packets);

        self.batches_with_kept_votes = self
            .batches_with_kept_votes
            .saturating_add(summary.batches_with_kept_votes as u64);
        self.batches_with_kept_certs = self
            .batches_with_kept_certs
            .saturating_add(summary.batches_with_kept_certs as u64);
        self.batches_with_kept_votes_and_certs = self
            .batches_with_kept_votes_and_certs
            .saturating_add(summary.batches_with_kept_votes_and_certs as u64);

        self.raw_vote_messages = self
            .raw_vote_messages
            .saturating_add(summary.raw_vote_messages);
        self.raw_cert_messages = self
            .raw_cert_messages
            .saturating_add(summary.raw_cert_messages);

        self.votes_to_verify = self.votes_to_verify.saturating_add(summary.votes_to_verify);
        self.certs_to_verify = self.certs_to_verify.saturating_add(summary.certs_to_verify);
        self.certs_sent_to_sigverify = self
            .certs_sent_to_sigverify
            .saturating_add(summary.certs_sent_to_sigverify);
        self.certs_skipped_seen = self
            .certs_skipped_seen
            .saturating_add(summary.certs_skipped_seen);

        self.discarded_packets = self
            .discarded_packets
            .saturating_add(summary.discarded_packets);
        self.malformed_packets = self
            .malformed_packets
            .saturating_add(summary.malformed_packets);
        self.missing_remote_pubkey = self
            .missing_remote_pubkey
            .saturating_add(summary.missing_remote_pubkey);
        self.old_certs = self.old_certs.saturating_add(summary.old_certs);
        self.generated_certs = self.generated_certs.saturating_add(summary.generated_certs);

        self.extract_filter_us = self
            .extract_filter_us
            .saturating_add(summary.extract_filter_us);
        self.cert_worker_send_us = self
            .cert_worker_send_us
            .saturating_add(summary.cert_worker_send_us);
        self.vote_path_us = self.vote_path_us.saturating_add(summary.vote_path_us);
        self.cert_reply_wait_us = self
            .cert_reply_wait_us
            .saturating_add(summary.cert_reply_wait_us);
        self.module_us = self.module_us.saturating_add(summary.module_us);

        self.sig_verified_votes = self
            .sig_verified_votes
            .saturating_add(summary.sig_verified_votes);
        self.vote_signature_failed = self
            .vote_signature_failed
            .saturating_add(summary.vote_signature_failed);
        self.vote_too_far_future = self
            .vote_too_far_future
            .saturating_add(summary.vote_too_far_future);

        self.cert_sig_verified = self
            .cert_sig_verified
            .saturating_add(summary.cert_sig_verified);
        self.cert_signature_failed = self
            .cert_signature_failed
            .saturating_add(summary.cert_signature_failed);
        self.cert_stake_failed = self
            .cert_stake_failed
            .saturating_add(summary.cert_stake_failed);
        self.cert_too_far_future = self
            .cert_too_far_future
            .saturating_add(summary.cert_too_far_future);
        self.cert_duplicates_skipped_before_verify = self
            .cert_duplicates_skipped_before_verify
            .saturating_add(summary.cert_duplicates_skipped_before_verify);

        self.configured_vote_threads = summary.configured_vote_threads;

        if summary.received_batches > self.max_received_batches {
            self.max_received_batches = summary.received_batches;
            self.max_received_batches_job = job_id;
        }

        if summary.max_packets_in_batch > self.max_packets_in_batch {
            self.max_packets_in_batch = summary.max_packets_in_batch;
            self.max_packets_in_batch_job = job_id;
        }

        if summary.input_packets > self.max_input_packets {
            self.max_input_packets = summary.input_packets;
            self.max_input_packets_job = job_id;
        }

        if summary.votes_to_verify > self.max_votes_to_verify {
            self.max_votes_to_verify = summary.votes_to_verify;
            self.max_votes_to_verify_job = job_id;
        }

        if summary.certs_to_verify > self.max_certs_to_verify {
            self.max_certs_to_verify = summary.certs_to_verify;
            self.max_certs_to_verify_job = job_id;
        }

        if summary.vote_path_us > self.max_vote_path_us {
            self.max_vote_path_us = summary.vote_path_us;
            self.max_vote_path_job = job_id;
        }

        if summary.cert_reply_wait_us > self.max_cert_reply_wait_us {
            self.max_cert_reply_wait_us = summary.cert_reply_wait_us;
            self.max_cert_reply_wait_job = job_id;
        }

        if summary.module_us > self.max_module_us {
            self.max_module_us = summary.module_us;
            self.max_module_job = job_id;
        }
    }
}

impl Display for AggregatedVerifySummary {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let rejected_votes_before_sigverify =
            self.raw_vote_messages.saturating_sub(self.votes_to_verify);

        let avg_sent_batches_per_job = avg_u64(self.received_batches, self.jobs);
        let avg_votes_per_job = avg_u64(self.votes_to_verify, self.jobs);
        let avg_certs_per_job = avg_u64(self.certs_to_verify, self.jobs);

        let vote_verify_ms_per_vote = avg_u64(self.vote_path_us, self.votes_to_verify) / 1000.0;
        let module_ms_per_vote = avg_u64(self.module_us, self.votes_to_verify) / 1000.0;

        let avg_vote_verify_ms_per_job = avg_u64(self.vote_path_us, self.jobs) / 1000.0;
        let avg_module_ms_per_job = avg_u64(self.module_us, self.jobs) / 1000.0;

        writeln!(f, "=== BLS replay verifier summary ===")?;
        writeln!(f, "Input")?;
        writeln!(f, "  packets received:            {}", self.input_packets)?;
        writeln!(
            f,
            "  votes received / accepted:   {} / {}",
            self.raw_vote_messages, self.votes_to_verify
        )?;
        writeln!(
            f,
            "  certs received / accepted:   {} / {}",
            self.raw_cert_messages, self.certs_to_verify
        )?;
        writeln!(
            f,
            "  certs sent to sigverify:     {}",
            self.certs_sent_to_sigverify
        )?;
        writeln!(
            f,
            "  certs skipped seen-cache:    {}",
            self.certs_skipped_seen
        )?;
        writeln!(
            f,
            "  rejected votes before sigverify: {}",
            rejected_votes_before_sigverify
        )?;
        writeln!(
            f,
            "  discarded / malformed pkts:  {} / {}",
            self.discarded_packets, self.malformed_packets
        )?;

        writeln!(f, "Batching seen by verifier")?;
        writeln!(f, "  verify jobs:                 {}", self.jobs)?;
        writeln!(
            f,
            "  sent PacketBatches drained:  {}",
            self.received_batches
        )?;
        writeln!(
            f,
            "  avg PacketBatches/job:       {:.2}",
            avg_sent_batches_per_job
        )?;
        writeln!(f, "  avg votes/job:               {:.2}", avg_votes_per_job)?;
        writeln!(f, "  avg certs/job:               {:.2}", avg_certs_per_job)?;
        writeln!(
            f,
            "  max votes/job:               {} (job {})",
            self.max_votes_to_verify, self.max_votes_to_verify_job
        )?;
        writeln!(
            f,
            "  max certs/job:               {} (job {})",
            self.max_certs_to_verify, self.max_certs_to_verify_job
        )?;

        writeln!(f, "Vote result")?;
        writeln!(
            f,
            "  votes verified:              {}",
            self.sig_verified_votes
        )?;
        writeln!(
            f,
            "  signature failures:          {}",
            self.vote_signature_failed
        )?;
        writeln!(
            f,
            "  too far future:              {}",
            self.vote_too_far_future
        )?;

        writeln!(f, "Cert result")?;
        writeln!(
            f,
            "  certs verified:              {}",
            self.cert_sig_verified
        )?;
        writeln!(
            f,
            "  signature failures:          {}",
            self.cert_signature_failed
        )?;
        writeln!(
            f,
            "  stake failures:              {}",
            self.cert_stake_failed
        )?;
        writeln!(
            f,
            "  too far future:              {}",
            self.cert_too_far_future
        )?;
        writeln!(
            f,
            "  duplicates skipped:        {}",
            self.cert_duplicates_skipped_before_verify
        )?;

        writeln!(f, "Timing")?;
        writeln!(
            f,
            "  vote verifier total:         {:.3} ms",
            us_to_ms(self.vote_path_us)
        )?;
        writeln!(
            f,
            "  vote verifier cost:          {:.6} ms/vote",
            vote_verify_ms_per_vote
        )?;
        writeln!(
            f,
            "  full verifier job total:           {:.3} ms",
            us_to_ms(self.module_us)
        )?;
        writeln!(
            f,
            "  full verifier job cost:            {:.6} ms/vote",
            module_ms_per_vote
        )?;
        writeln!(
            f,
            "  avg job time:                {:.3} ms verify / {:.3} ms module",
            avg_vote_verify_ms_per_job, avg_module_ms_per_job
        )?;
        writeln!(
            f,
            "  max job time:                {:.3} ms verify / {:.3} ms module",
            us_to_ms(self.max_vote_path_us),
            us_to_ms(self.max_module_us)
        )?;

        writeln!(f, "Overhead / sanity")?;
        writeln!(
            f,
            "  extract + filter total:      {:.3} ms",
            us_to_ms(self.extract_filter_us)
        )?;
        writeln!(
            f,
            "  cert worker send total:      {:.3} ms",
            us_to_ms(self.cert_worker_send_us)
        )?;
        writeln!(
            f,
            "  cert reply wait total:       {:.3} ms",
            us_to_ms(self.cert_reply_wait_us)
        )?;
        writeln!(
            f,
            "  missing remote pubkey:       {}",
            self.missing_remote_pubkey
        )?;
        writeln!(
            f,
            "  old / generated certs:       {} / {}",
            self.old_certs, self.generated_certs
        )?;

        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
struct ReplayPacingReport {
    scheduled_end_us: u64,
    actual_send_end_us: u64,
    max_schedule_lag_us: u64,
    max_send_block_us: u64,
    total_send_block_us: u64,
    blocked_sends_over_threshold: u64,
}

impl ReplayPacingReport {
    fn new(scheduled_end_us: u64) -> Self {
        Self {
            scheduled_end_us,
            actual_send_end_us: 0,
            max_schedule_lag_us: 0,
            max_send_block_us: 0,
            total_send_block_us: 0,
            blocked_sends_over_threshold: 0,
        }
    }

    fn record_send_result(
        &mut self,
        schedule_lag_us: u64,
        send_block_us: u64,
        actual_send_end_us: u64,
    ) {
        self.actual_send_end_us = actual_send_end_us;
        self.max_schedule_lag_us = self.max_schedule_lag_us.max(schedule_lag_us);
        self.max_send_block_us = self.max_send_block_us.max(send_block_us);
        self.total_send_block_us = self.total_send_block_us.saturating_add(send_block_us);

        if send_block_us > SEND_BLOCK_WARN_US {
            self.blocked_sends_over_threshold = self.blocked_sends_over_threshold.saturating_add(1);
        }
    }
}

impl Display for ReplayPacingReport {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== Replay pacing ===")?;
        writeln!(
            f,
            "  scheduled duration:          {:.3} ms",
            us_to_ms(self.scheduled_end_us)
        )?;
        writeln!(
            f,
            "  actual send end:             {:.3} ms",
            us_to_ms(self.actual_send_end_us)
        )?;
        writeln!(
            f,
            "  send lag:                    {:.3} ms",
            us_to_ms(
                self.actual_send_end_us
                    .saturating_sub(self.scheduled_end_us)
            )
        )?;
        writeln!(
            f,
            "  max schedule lag:            {:.3} ms",
            us_to_ms(self.max_schedule_lag_us)
        )?;
        writeln!(
            f,
            "  max send block time:         {:.3} ms",
            us_to_ms(self.max_send_block_us)
        )?;
        writeln!(
            f,
            "  total send block time:       {:.3} ms",
            us_to_ms(self.total_send_block_us)
        )?;
        writeln!(
            f,
            "  blocked sends > {}us:        {}",
            SEND_BLOCK_WARN_US, self.blocked_sends_over_threshold
        )?;

        Ok(())
    }
}

#[derive(Debug)]
pub struct ReplayReport {
    pacing: ReplayPacingReport,
    vote_latency: VoteBatchLatencySummary,
    verifier: AggregatedVerifySummary,
    output: OutputRow,
}

impl Display for ReplayReport {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f)?;
        writeln!(f, "{}", self.pacing)?;
        writeln!(f)?;
        writeln!(f, "{}", self.vote_latency)?;
        writeln!(f)?;
        writeln!(f, "{}", self.verifier)?;
        writeln!(f)?;
        writeln!(f, "=== Replay configuration ===")?;
        writeln!(f, "  seed:                         {}", self.output.seed)?;
        writeln!(
            f,
            "  arrival_pattern:              {:?}",
            self.output.arrival_pattern
        )?;
        writeln!(
            f,
            "  batch_window_us:              {}",
            self.output.batch_window_us
        )?;
        writeln!(
            f,
            "  max_packets_per_batch:        {}",
            self.output.max_packets_per_batch
        )?;
        writeln!(
            f,
            "  emitted_batches:              {}",
            self.output.emitted_batches
        )?;
        writeln!(
            f,
            "  avg_packets_per_batch:        {:.2}",
            self.output.avg_packets_per_batch
        )?;
        writeln!(
            f,
            "  num_slots:                    {}",
            self.output.num_slots
        )?;
        writeln!(
            f,
            "  votes_per_slot:               {}",
            self.output.votes_per_slot
        )?;
        writeln!(
            f,
            "  certs_per_slot:               {}",
            self.output.certs_per_slot
        )?;
        writeln!(
            f,
            "  base_slot:                    {}",
            self.output.base_slot
        )?;
        writeln!(
            f,
            "  slot_window_us:               {}",
            self.output.slot_window_us
        )?;
        writeln!(
            f,
            "  cert_signers:                 {}",
            self.output.cert_signers
        )?;
        writeln!(
            f,
            "  cert_ratio:                   {:.3}",
            self.output.cert_ratio
        )?;
        writeln!(
            f,
            "  vote_ratio:                   {:.3}",
            self.output.vote_ratio
        )?;
        writeln!(
            f,
            "  num_threads:                  {}",
            self.output.num_threads
        )?;
        writeln!(
            f,
            "  num_validators:               {}",
            self.output.num_validators
        )?;
        writeln!(
            f,
            "  total_packets:                {}",
            self.output.total_packets
        )?;
        writeln!(
            f,
            "  vote_packets:                 {}",
            self.output.vote_packets
        )?;
        writeln!(
            f,
            "  cert_packets:                 {}",
            self.output.cert_packets
        )?;
        writeln!(
            f,
            "  sigverify_total_us:           {}",
            self.output.sigverify_total_us
        )?;
        writeln!(
            f,
            "  sigverify_avg_us_per_slot:    {:.2}",
            self.output.sigverify_avg_us_per_slot
        )?;
        writeln!(
            f,
            "  sigverify_max_us_per_slot:    {}",
            self.output.sigverify_max_us_per_slot
        )?;
        writeln!(
            f,
            "  sigverify_max_slot:           {}",
            self.output.sigverify_max_slot
        )?;
        writeln!(
            f,
            "  elapsed_us:                   {}",
            self.output.elapsed_us
        )?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct ReplayMetricsCollector {
    pacing: ReplayPacingReport,
    vote_latency_tracker: VoteBatchLatencyTracker,
}

impl ReplayMetricsCollector {
    pub fn new(scheduled_end_us: u64) -> Self {
        Self {
            pacing: ReplayPacingReport::new(scheduled_end_us),
            vote_latency_tracker: VoteBatchLatencyTracker::default(),
        }
    }

    pub fn record_pending_batch(&self, batch_seq: u64, vote_count: usize) {
        self.vote_latency_tracker
            .push_pending_batch(batch_seq, vote_count, Instant::now());
    }

    pub fn record_send_result(
        &mut self,
        schedule_lag_us: u64,
        send_block_us: u64,
        actual_send_end_us: u64,
    ) {
        self.pacing
            .record_send_result(schedule_lag_us, send_block_us, actual_send_end_us);
    }

    pub fn build_report(
        self,
        summaries: &[VerifyBatchSummary],
        base_slot: Slot,
        num_slots: usize,
        mut output: OutputRow,
    ) -> ReplayReport {
        let mut timing = PerSlotTiming::new(base_slot, num_slots);
        let mut verifier = AggregatedVerifySummary::default();

        for summary in summaries {
            self.vote_latency_tracker
                .mark_next_batches_done(summary.received_batches, summary.vote_done_at);

            timing.record(summary);
            verifier.record(summary);
        }

        let timing_summary = timing.summary();

        output.sigverify_total_us = timing_summary.total_us;
        output.sigverify_avg_us_per_slot = timing_summary.avg_us_per_slot;
        output.sigverify_max_us_per_slot = timing_summary.max_us_per_slot;
        output.sigverify_max_slot = timing_summary.max_slot;

        ReplayReport {
            pacing: self.pacing,
            vote_latency: self.vote_latency_tracker.summary(),
            verifier,
            output,
        }
    }
}

pub fn print_debug_timed_batches(
    workload: &StoredWorkload,
    batch_window_us: u64,
    max_packets_per_batch: usize,
    debug_batches: usize,
) {
    if debug_batches == 0 {
        return;
    }

    eprintln!("debug: first {debug_batches} timed batches after replay reshuffle:");

    for batch in debug_timed_batches(
        workload,
        batch_window_us,
        max_packets_per_batch,
        debug_batches,
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
pub fn print_debug_send(
    index: usize,
    debug_batches: usize,
    scheduled_send_at_us: u64,
    before_send_us: u64,
    actual_send_end_us: u64,
    schedule_lag_us: u64,
    send_block_us: u64,
    vote_count: usize,
) {
    if index >= debug_batches {
        return;
    }

    eprintln!(
        "debug send #{index:04}: scheduled_send_at_us={scheduled_send_at_us}, \
         before_send_us={before_send_us}, actual_send_end_us={actual_send_end_us}, \
         schedule_lag_us={schedule_lag_us}, send_block_us={send_block_us}, \
         vote_count={vote_count}",
    );
}
