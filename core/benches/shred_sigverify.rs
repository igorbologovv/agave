#![allow(clippy::arithmetic_side_effects)]

use {
    crossbeam_channel::unbounded,
    solana_entry::entry::create_ticks,
    solana_gossip::{cluster_info::ClusterInfo, contact_info::ContactInfo},
    solana_hash::Hash,
    solana_keypair::Keypair,
    solana_ledger::{
        genesis_utils::create_genesis_config_with_leader,
        leader_schedule_cache::LeaderScheduleCache,
        shred::{
            DATA_SHREDS_PER_FEC_BLOCK, ProcessShredsStats, ReedSolomonCache, Shredder,
            get_data_shred_bytes_per_batch_typical, max_ticks_per_n_shreds,
        },
    },
    solana_net_utils::SocketAddrSpace,
    solana_perf::packet::{PacketBatch, RecycledPacketBatch},
    solana_runtime::{bank::Bank, bank_forks::BankForks},
    solana_signer::Signer,
    solana_streamer::evicting_sender::EvictingSender,
    solana_time_utils::timestamp,
    solana_turbine::sigverify_shreds::{RepairNonceLocationLookup, spawn_shred_sigverify},
    std::{
        env,
        fs::{File, OpenOptions},
        io::{BufRead, BufReader, Write},
        num::NonZeroUsize,
        sync::Arc,
        thread,
        time::{Duration, Instant},
    },
};

const SHREDS_PER_SECOND: usize = 6_250;
const SHREDS_PER_SLOT: usize = 2_500;
const PACKETS_PER_BATCH: usize = 64;
const DEFAULT_NUM_SLOTS: usize = 50;
const DEFAULT_NUM_SIGVERIFY_THREADS: usize = 4;
const FIRST_SLOT: u64 = 1;

/// Optional control channel for `perf stat`.
///
/// When PERF_CTL_FIFO is set, counters can be started only after the workload
/// has been prepared and the sigverify workers have been spawned.
///
/// PERF_CTL_ACK_FIFO is optional, but when present it synchronizes enable/disable
/// with perf before the benchmark proceeds.
struct PerfControl {
    control: Option<File>,
    ack: Option<BufReader<File>>,
}

impl PerfControl {
    fn from_env() -> Self {
        let control_path = env::var_os("PERF_CTL_FIFO");
        let ack_path = env::var_os("PERF_CTL_ACK_FIFO");

        match control_path {
            Some(control_path) => {
                let control = OpenOptions::new()
                    .write(true)
                    .open(control_path)
                    .expect("open perf control fifo");

                let ack = ack_path.map(|ack_path| {
                    BufReader::new(
                        OpenOptions::new()
                            .read(true)
                            .open(ack_path)
                            .expect("open perf ack fifo"),
                    )
                });

                Self {
                    control: Some(control),
                    ack,
                }
            }
            None => {
                assert!(
                    ack_path.is_none(),
                    "PERF_CTL_ACK_FIFO requires PERF_CTL_FIFO"
                );

                Self {
                    control: None,
                    ack: None,
                }
            }
        }
    }

    fn command(&mut self, command: &str) {
    let Some(control) = self.control.as_mut() else {
        return;
    };

    writeln!(control, "{command}").expect("write perf control command");
    control.flush().expect("flush perf control command");

    if let Some(ack) = self.ack.as_mut() {
        let mut response = String::new();
        ack.read_line(&mut response).expect("read perf ack");

        assert_eq!(
            response.trim_matches(|c: char| c == '\0' || c.is_whitespace()),
            "ack"
        );
    }
}

    fn enable(&mut self) {
        self.command("enable");
    }

    fn disable(&mut self) {
        self.command("disable");
    }
}

fn env_usize(name: &str, default: usize) -> usize {
    match env::var(name) {
        Ok(value) => value
            .parse::<usize>()
            .unwrap_or_else(|_| panic!("{name} must be a positive integer")),
        Err(_) => default,
    }
}

fn shred_size_typical() -> usize {
    let batch_payload = get_data_shred_bytes_per_batch_typical() as usize;
    batch_payload / DATA_SHREDS_PER_FEC_BLOCK
}

fn make_slot_batches(
    leader_keypair: &Keypair,
    slot: u64,
    shreds_per_slot: usize,
) -> Vec<PacketBatch> {
    let shred_size = shred_size_typical();

    // Same sizing logic already used by the existing shredder benchmark.
    // Generate enough tick data to produce at least the requested number
    // of shreds. Generation happens before perf counters are enabled.
    let ticks_per_shred = max_ticks_per_n_shreds(1, Some(shred_size)).max(1);
    let num_ticks = ticks_per_shred * shreds_per_slot as u64;

    let entries = create_ticks(num_ticks, 0, Hash::new_unique());

    let shredder = Shredder::new(
        slot,
        slot.saturating_sub(1),
        0,
        0,
    )
    .unwrap();

    // `false` deliberately avoids turning the benchmark into a
    // retransmitter-resigning benchmark. The first workload is intended
    // to measure the normal shred verification path.
    let (data_shreds, coding_shreds) = shredder.entries_to_merkle_shreds_for_tests(
        leader_keypair,
        &entries,
        false,
        Hash::new_unique(),
        0,
        0,
        &ReedSolomonCache::default(),
        &mut ProcessShredsStats::default(),
    );

    let mut shreds = data_shreds;
    shreds.extend(coding_shreds);

    assert!(
        shreds.len() >= shreds_per_slot,
        "shred generator produced {} shreds, expected at least {}",
        shreds.len(),
        shreds_per_slot,
    );

    shreds.truncate(shreds_per_slot);

    shreds
        .chunks(PACKETS_PER_BATCH)
        .map(|shreds| {
            let mut batch = RecycledPacketBatch::with_capacity(shreds.len());

            for shred in shreds {
                batch.push(shred.payload().to_packet(None));
            }

            PacketBatch::from(batch)
        })
        .collect()
}

fn make_workload(
    leader_keypair: &Keypair,
    num_slots: usize,
) -> Vec<PacketBatch> {
    let batches_per_slot = SHREDS_PER_SLOT.div_ceil(PACKETS_PER_BATCH);

    let mut workload = Vec::with_capacity(num_slots * batches_per_slot);

    for slot_offset in 0..num_slots {
        let slot = FIRST_SLOT + slot_offset as u64;

        workload.extend(make_slot_batches(
            leader_keypair,
            slot,
            SHREDS_PER_SLOT,
        ));
    }

    workload
}

fn arrival_offset(num_shreds: usize) -> Duration {
    let nanos = num_shreds as u128 * 1_000_000_000u128
        / SHREDS_PER_SECOND as u128;

    Duration::from_nanos(nanos as u64)
}

fn sleep_until(deadline: Instant) {
    loop {
        let now = Instant::now();

        if now >= deadline {
            return;
        }

        thread::sleep(deadline - now);
    }
}

fn main() {
    let num_slots = env_usize(
        "SHRED_SIGVERIFY_SLOTS",
        DEFAULT_NUM_SLOTS,
    );

    let num_sigverify_threads = NonZeroUsize::new(env_usize(
        "SHRED_SIGVERIFY_THREADS",
        DEFAULT_NUM_SIGVERIFY_THREADS,
    ))
    .expect("SHRED_SIGVERIFY_THREADS must be greater than zero");

    assert!(num_slots > 0);

    let leader_keypair = Arc::new(Keypair::new());
    let leader_pubkey = leader_keypair.pubkey();

    // The validator running sigverify must not be the leader. get_slot_leaders()
    // intentionally rejects shreds produced by the validator itself.
    let node_keypair = Arc::new(Keypair::new());
    let node_pubkey = node_keypair.pubkey();

    //
    // Prepare the complete workload before starting perf counters.
    //
    let workload = make_workload(
        leader_keypair.as_ref(),
        num_slots,
    );

    let expected_shreds = num_slots * SHREDS_PER_SLOT;

    assert_eq!(
        workload.iter().map(PacketBatch::len).sum::<usize>(),
        expected_shreds,
    );

    let bank = Bank::new_for_tests(
        &create_genesis_config_with_leader(
            100,
            &leader_pubkey,
            10,
        )
        .genesis_config,
    );

    let leader_schedule_cache =
        Arc::new(LeaderScheduleCache::new_from_bank(&bank));

    let bank_forks = BankForks::new_rw_arc(bank);

    let cluster_info = Arc::new(ClusterInfo::new(
        ContactInfo::new_localhost(
            &node_pubkey,
            timestamp(),
        ),
        node_keypair,
        SocketAddrSpace::Unspecified,
    ));

    //
    // An unbounded ingress channel is intentional here.
    //
    // The pacing producer must never be blocked by the harness itself.
    // If sigverify cannot sustain the requested rate, the queue is allowed
    // to accumulate rather than modifying the arrival schedule.
    //
    let (shred_fetch_sender, shred_fetch_receiver) =
        unbounded::<PacketBatch>();

    //
    // We are benchmarking shred sigverify, not retransmit stage consumption.
    // EvictingSender keeps this output non-blocking, as in production.
    //
    let (retransmit_sender, _retransmit_receiver) =
        EvictingSender::new_bounded(1);

    //
    // TVU also uses an unbounded verified-shred channel.
    // We deliberately drain it only after perf counters are disabled so
    // receiver-side benchmark bookkeeping is not included in CPU measurements.
    //
    let (verified_sender, verified_receiver) = unbounded();

    let repair_nonce_location_lookup:
        Arc<RepairNonceLocationLookup> =
        Arc::new(|_| None);

    //
    // Worker creation is outside the measured section.
    //
    let sigverify_handle = spawn_shred_sigverify(
        cluster_info,
        bank_forks,
        leader_schedule_cache,
        shred_fetch_receiver,
        retransmit_sender,
        verified_sender,
        repair_nonce_location_lookup,
        num_sigverify_threads,
    );

    let mut perf = PerfControl::from_env();

    //
    // Measurement starts here.
    //
    perf.enable();

    let replay_start = Instant::now();
    let mut sent_shreds = 0usize;

    for batch in workload {
        let deadline =
            replay_start + arrival_offset(sent_shreds);

        sleep_until(deadline);

        let batch_len = batch.len();

        shred_fetch_sender
            .send(batch)
            .expect("shred sigverify receiver disconnected");

        sent_shreds += batch_len;
    }

    assert_eq!(sent_shreds, expected_shreds);

    //
    // Closing ingress lets sigverify consume everything already queued
    // and terminate once the workload has completely drained.
    //
    drop(shred_fetch_sender);

    sigverify_handle
        .join()
        .expect("shred sigverify thread panicked");

    //
    // Measurement ends only after all queued shred verification work
    // has completed, so tail-drain CPU is included.
    //
    perf.disable();

    //
    // Validation happens outside the measured region.
    //
    let verified_shreds = verified_receiver
        .try_iter()
        .map(|shreds| shreds.len())
        .sum::<usize>();

    assert_eq!(
        verified_shreds,
        expected_shreds,
        "some shreds did not survive sigverify",
    );
}