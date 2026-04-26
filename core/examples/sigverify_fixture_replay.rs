//! Replay a previously generated slot-based synthetic sigverify fixture and measure only
//! the verification pipeline time.

extern crate clap4 as clap;

#[path = "support/sigverify_fixture_common.rs"]
mod sigverify_fixture_common;

use {
    clap::Parser,
    sigverify_fixture_common::{
        OutputRow, ReplayConfig, init_example_context, load_workload_from_file, print_results,
        stored_workload_to_streamer_batches, validate_replay_config,
    },
    std::{convert::TryFrom, time::Instant},
};

fn main() {
    let config = ReplayConfig::parse();
    validate_replay_config(&config).unwrap_or_else(|err| {
        eprintln!("error: {err}");
        std::process::exit(1);
    });

    let workload = load_workload_from_file(&config.input).unwrap_or_else(|err| {
        eprintln!("error: failed to load fixture: {err}");
        std::process::exit(1);
    });

    let mut ctx = init_example_context(config.num_threads, workload.num_validators, workload.seed);

    let batches = stored_workload_to_streamer_batches(
        &workload,
        config.poll_interval_us,
        config.max_packets_per_batch,
    );

    let emitted_batches = batches.len();
    let avg_packets_per_batch = if emitted_batches == 0 {
        0.0
    } else {
        workload.total_packets as f64 / emitted_batches as f64
    };

    eprintln!(
        "Prepare phase is over; Start Verify Pipeline \
         (emitted_batches={}, avg_packets_per_batch={:.2})",
        emitted_batches, avg_packets_per_batch
    );

    let start = Instant::now();

    for batch in batches {
        ctx.verifier.verify_and_send_batches_for_tests(vec![batch]);
    }

    ctx.verifier.print_cert_thread_metrics_for_tests();

    let elapsed = start.elapsed();
    let elapsed_us =
        u64::try_from(elapsed.as_micros()).expect("elapsed microseconds must fit into u64");

    let per_packet_us = elapsed_us
        .checked_div(
            u64::try_from(workload.total_packets).expect("total_packets must fit into u64"),
        )
        .expect("total_packets must be > 0");

    let cert_ratio = workload.cert_packets as f64 / workload.total_packets as f64;
    let vote_ratio = workload.vote_packets as f64 / workload.total_packets as f64;

    let row = OutputRow {
        seed: workload.seed,
        poll_interval_us: config.poll_interval_us,
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
        elapsed_us,
        per_packet_us,
    };

    print_results(&row, config.csv);
}