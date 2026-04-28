//! Replay a previously generated slot-based synthetic sigverify fixture through the
//! real sigverifier packet channel.

extern crate clap4 as clap;

#[path = "support/sigverify_fixture_common.rs"]
mod sigverify_fixture_common;

use {
    clap::Parser,
    sigverify_fixture_common::{
        debug_timed_batches, init_example_context, load_workload_from_file, make_timed_batches,
        print_results, reshuffle_workload_for_replay, validate_replay_config, ExampleContext,
        OutputRow, ReplayConfig,
    },
    std::{
        convert::TryFrom,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        thread,
        time::{Duration, Instant},
    },
};

const SEND_BLOCK_WARN_US: u64 = 100;

fn wait_until(start: Instant, send_at_us: u64) {
    let target = start + Duration::from_micros(send_at_us);

    loop {
        let now = Instant::now();

        if now >= target {
            return;
        }

        let remaining = target.duration_since(now);

        if remaining > Duration::from_micros(100) {
            thread::sleep(remaining - Duration::from_micros(50));
        } else {
            std::hint::spin_loop();
        }
    }
}

fn elapsed_us_since(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_micros()).expect("elapsed microseconds must fit into u64")
}

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

    let workload = reshuffle_workload_for_replay(&workload, &config);

    if config.debug_batches > 0 {
        eprintln!(
            "debug: first {} timed batches after replay reshuffle:",
            config.debug_batches
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

    let scheduled_end_us = timed_batches.last().map_or(0, |batch| batch.send_at_us);

    eprintln!(
        "Prepare phase is over; Start paced replay \
         (arrival_pattern={:?}, emitted_batches={}, avg_packets_per_batch={:.2}, scheduled_end_us={})",
        config.arrival_pattern,
        emitted_batches,
        avg_packets_per_batch,
        scheduled_end_us,
    );

    let ctx = init_example_context(config.num_threads, workload.num_validators, workload.seed);

    let ExampleContext {
        verifier,
        packet_sender,
        _repair_receiver,
        _reward_receiver,
        _pool_receiver,
        _metrics_receiver,
        ..
    } = ctx;

    let _keep_receivers_alive = (
        _repair_receiver,
        _reward_receiver,
        _pool_receiver,
        _metrics_receiver,
    );

    let exit = Arc::new(AtomicBool::new(false));

    let verifier_thread = {
        let exit = Arc::clone(&exit);

        thread::Builder::new()
            .name("sigverifyReplayVerifier".to_string())
            .spawn(move || {
                verifier.run(exit);
            })
            .expect("failed to spawn sigverifier thread")
    };

    let replay_start = Instant::now();

    let mut actual_send_end_us = 0u64;
    let mut max_send_block_us = 0u64;
    let mut total_send_block_us = 0u64;
    let mut blocked_sends = 0u64;
    let mut max_schedule_lag_us = 0u64;

    for (batch_index, timed_batch) in timed_batches.into_iter().enumerate() {
        wait_until(replay_start, timed_batch.send_at_us);

        let before_send_us = elapsed_us_since(replay_start);
        let schedule_lag_us = before_send_us.saturating_sub(timed_batch.send_at_us);
        max_schedule_lag_us = max_schedule_lag_us.max(schedule_lag_us);

        let send_start = Instant::now();

        packet_sender
            .send(timed_batch.batch)
            .expect("failed to send packet batch to sigverifier");

        let send_block_us = u64::try_from(send_start.elapsed().as_micros())
            .expect("send elapsed microseconds must fit into u64");

        if send_block_us > SEND_BLOCK_WARN_US {
            blocked_sends = blocked_sends.saturating_add(1);
        }

        max_send_block_us = max_send_block_us.max(send_block_us);
        total_send_block_us = total_send_block_us.saturating_add(send_block_us);
        actual_send_end_us = elapsed_us_since(replay_start);

        if batch_index < config.debug_batches {
            eprintln!(
                "debug send #{:04}: scheduled_send_at_us={}, before_send_us={}, \
                 actual_send_end_us={}, schedule_lag_us={}, send_block_us={}",
                batch_index,
                timed_batch.send_at_us,
                before_send_us,
                actual_send_end_us,
                schedule_lag_us,
                send_block_us,
            );
        }
    }

    let send_lag_us = actual_send_end_us.saturating_sub(scheduled_end_us);

    eprintln!(
        "send schedule: scheduled_end_us={}, actual_send_end_us={}, send_lag_us={}, \
         max_schedule_lag_us={}, max_send_block_us={}, total_send_block_us={}, \
         blocked_sends_over_{}us={}",
        scheduled_end_us,
        actual_send_end_us,
        send_lag_us,
        max_schedule_lag_us,
        max_send_block_us,
        total_send_block_us,
        SEND_BLOCK_WARN_US,
        blocked_sends,
    );

    drop(packet_sender);
    exit.store(true, Ordering::Relaxed);

    verifier_thread
        .join()
        .expect("sigverifier thread panicked");

    let elapsed = replay_start.elapsed();
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
        elapsed_us,
        per_packet_us,
    };

    print_results(&row, config.csv);
}