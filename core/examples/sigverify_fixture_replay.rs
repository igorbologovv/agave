//! Replay a previously generated slot-based synthetic sigverify fixture through the
//! real sigverifier packet channel.

extern crate clap4 as clap;

#[path = "support/sigverify_fixture_common.rs"]
mod sigverify_fixture_common;

#[path = "support/sigverify_replay_report.rs"]
mod sigverify_replay_report;

use {
    clap::Parser,
    crossbeam_channel::unbounded,
    sigverify_fixture_common::{
        ExampleContext, OutputRow, ReplayConfig, fixture_max_slot, init_example_context,
        load_workload_from_file, make_timed_batches, reshuffle_workload_for_replay,
        validate_replay_config,
    },
    sigverify_replay_report::{
        ReplayMetricsCollector, count_votes_in_batch, print_debug_send, print_debug_timed_batches,
    },
    solana_core::bls_sigverify::bls_sigverifier::VerifyBatchSummary,
    std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        thread,
        time::{Duration, Instant},
    },
};

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

    let timed_batches = timed_batches
        .into_iter()
        .map(|timed_batch| {
            let vote_count = count_votes_in_batch(&timed_batch.batch);
            (timed_batch, vote_count)
        })
        .collect::<Vec<_>>();
    //if debug mode
    print_debug_timed_batches(
        &workload,
        config.batch_window_us,
        config.max_packets_per_batch,
        config.debug_batches,
    );

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

    let exit = Arc::new(AtomicBool::new(false));
    let verifier_exit = Arc::clone(&exit);

    let (summary_sender, summary_receiver) = unbounded::<VerifyBatchSummary>();

    let verifier_thread = thread::Builder::new()
        .name("sigverify-fixture-replay".to_string())
        .spawn(move || verifier.run_for_replay(verifier_exit, summary_sender))
        .expect("failed to spawn verifier thread");

    let replay_start = Instant::now();
    let mut collector = ReplayMetricsCollector::new(scheduled_end_us);

    for (index, (timed_batch, vote_count)) in timed_batches.into_iter().enumerate() {
        let scheduled_send_at_us = timed_batch.send_at_us;

        wait_until(replay_start, scheduled_send_at_us);

        let before_send_us = replay_start.elapsed().as_micros() as u64;
        let schedule_lag_us = before_send_us.saturating_sub(scheduled_send_at_us);

        collector.record_pending_batch(index as u64, vote_count);

        let send_start = Instant::now();

        packet_sender
            .send(timed_batch.batch)
            .expect("packet receiver disconnected");

        let send_block_us = send_start.elapsed().as_micros() as u64;
        let actual_send_end_us = replay_start.elapsed().as_micros() as u64;

        collector.record_send_result(schedule_lag_us, send_block_us, actual_send_end_us);

        print_debug_send(
            index,
            config.debug_batches,
            scheduled_send_at_us,
            before_send_us,
            actual_send_end_us,
            schedule_lag_us,
            send_block_us,
            vote_count,
        );
    }

    while packet_sender.len() > 0 {
        thread::sleep(Duration::from_millis(1));
    }

    exit.store(true, Ordering::Relaxed);
    drop(packet_sender);

    verifier_thread
        .join()
        .expect("verifier thread panicked during replay");

    let summaries = summary_receiver.try_iter().collect::<Vec<_>>();
    let elapsed_us = replay_start.elapsed().as_micros() as u64;

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

    let report = collector.build_report(
        &summaries,
        workload.base_slot,
        workload.num_slots,
        OutputRow {
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

            sigverify_total_us: 0,
            sigverify_avg_us_per_slot: 0.0,
            sigverify_max_us_per_slot: 0,
            sigverify_max_slot: workload.base_slot,

            elapsed_us,
        },
    );

    print!("{report}");
}
