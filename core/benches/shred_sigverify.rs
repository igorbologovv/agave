#![allow(clippy::arithmetic_side_effects)]

#[cfg(not(any(target_env = "msvc", target_os = "freebsd")))]
#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;

use {
    crossbeam_channel::bounded,
    solana_entry::entry::create_ticks,
    solana_gossip::{cluster_info::ClusterInfo, contact_info::ContactInfo},
    solana_hash::Hash,
    solana_keypair::Keypair,
    solana_ledger::{
    genesis_utils::create_genesis_config_with_leader,
    leader_schedule_cache::LeaderScheduleCache,
    shred::{
    self, DATA_SHREDS_PER_FEC_BLOCK, ProcessShredsStats, ReedSolomonCache, ShredId,
    Shredder, get_data_shred_bytes_per_batch_typical, max_ticks_per_n_shreds,
},
    sigverify_shreds::{
        reset_sigverify_debug_counters,
        sigverify_debug_counters,
    },
},
    solana_net_utils::SocketAddrSpace,
    solana_perf::packet::{Packet, PacketBatch, RecycledPacketBatch},
    solana_runtime::{bank::Bank, bank_forks::BankForks},
    solana_signer::Signer,
    solana_streamer::evicting_sender::EvictingSender,
    solana_time_utils::timestamp,
    solana_turbine::sigverify_shreds::{RepairNonceLocationLookup, spawn_shred_sigverify},
    std::{
        collections::HashSet,
        env,
        fs::{File, OpenOptions},
        io::{BufRead, BufReader, Write},
        num::NonZeroUsize,
        sync::Arc,
        thread,
        time::{Duration, Instant},
    },
};

const SLOT_DURATION: Duration = Duration::from_millis(400);

const PACKETS_PER_BATCH: usize = 64;
const CHANNEL_CAPACITY: usize = 1_024;

const DEFAULT_NUM_SLOTS: usize = 50;
const DEFAULT_BATCHES_PER_SLOT: usize = 500;
const DEFAULT_INVALID_PACKETS_PER_SLOT: usize = 0;
const DEFAULT_NUM_SIGVERIFY_THREADS: usize = 4;

const FIRST_SLOT: u64 = 1;

/// Optional control channel for `perf stat`.
///
/// When PERF_CTL_FIFO is set, counters can be started after workload
/// preparation and worker creation.
///
/// PERF_CTL_ACK_FIFO is optional. When present it synchronizes enable/disable
/// commands with perf.
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
            .unwrap_or_else(|_| panic!("{name} must be an unsigned integer")),
        Err(_) => default,
    }
}

fn shred_size_typical() -> usize {
    let batch_payload = get_data_shred_bytes_per_batch_typical() as usize;
    batch_payload / DATA_SHREDS_PER_FEC_BLOCK
}

fn should_corrupt_packet(
    packet_index: usize,
    packets_per_slot: usize,
    invalid_packets_per_slot: usize,
) -> bool {
    if invalid_packets_per_slot == 0 {
        return false;
    }

    packet_index * invalid_packets_per_slot / packets_per_slot
        != (packet_index + 1) * invalid_packets_per_slot / packets_per_slot
}

fn corrupt_shred_signature(packet: &mut Packet) {
    // The leader signature starts at the beginning of the shred payload.
    // Flipping one signature byte keeps the shred layout intact while making
    // signature verification fail.
    packet.buffer_mut()[0] ^= 1;
}

fn make_slot_batches(
    leader_keypair: &Keypair,
    slot: u64,
    batches_per_slot: usize,
    invalid_packets_per_slot: usize,
) -> (
    Vec<PacketBatch>,
    HashSet<ShredId>,
    HashSet<ShredId>,
) {
    let shreds_per_slot = batches_per_slot * PACKETS_PER_BATCH;
    let shred_size = shred_size_typical();

    let ticks_per_shred = max_ticks_per_n_shreds(1, Some(shred_size)).max(1);
    let num_ticks = ticks_per_shred * shreds_per_slot as u64;

    let entries = create_ticks(num_ticks, 0, Hash::new_unique());
    let shredder = Shredder::new(slot, slot.saturating_sub(1), 0, 0).unwrap();

    // Use variants without retransmitter signatures so the workload primarily
    // measures leader signature verification.
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

    let mut batches = Vec::with_capacity(batches_per_slot);
    let mut expected_valid_ids =
        HashSet::<ShredId>::with_capacity(shreds_per_slot - invalid_packets_per_slot);
    let mut expected_invalid_ids =
        HashSet::<ShredId>::with_capacity(invalid_packets_per_slot);
    let mut seen_ids = HashSet::<ShredId>::with_capacity(shreds_per_slot);
    let mut corrupted_packets = 0usize;

    for (batch_index, shreds) in shreds.chunks(PACKETS_PER_BATCH).enumerate() {
        let mut batch = RecycledPacketBatch::with_capacity(shreds.len());

        for (packet_index, shred) in shreds.iter().enumerate() {
            let slot_packet_index = batch_index * PACKETS_PER_BATCH + packet_index;
            let shred_id = shred.id();

            assert!(
                seen_ids.insert(shred_id),
                "workload contains duplicate shred id: {shred_id:?}"
            );

            let mut packet = shred.payload().to_packet(None);

            if should_corrupt_packet(
                slot_packet_index,
                shreds_per_slot,
                invalid_packets_per_slot,
            ) {
                assert!(
                    expected_invalid_ids.insert(shred_id),
                    "duplicate intentionally invalid shred id: {shred_id:?}"
                );
                corrupt_shred_signature(&mut packet);
                corrupted_packets += 1;
            } else {
                assert!(
                    expected_valid_ids.insert(shred_id),
                    "duplicate expected-valid shred id: {shred_id:?}"
                );
            }

            batch.push(packet);
        }

        batches.push(PacketBatch::from(batch));
    }

    assert_eq!(batches.len(), batches_per_slot);
    assert_eq!(corrupted_packets, invalid_packets_per_slot);
    assert_eq!(seen_ids.len(), shreds_per_slot);
    assert_eq!(
        expected_valid_ids.len(),
        shreds_per_slot - invalid_packets_per_slot
    );
    assert_eq!(expected_invalid_ids.len(), invalid_packets_per_slot);

    (
        batches,
        expected_valid_ids,
        expected_invalid_ids,
    )
}

fn make_workload(
    leader_keypair: &Keypair,
    num_slots: usize,
    batches_per_slot: usize,
    invalid_packets_per_slot: usize,
) -> (
    Vec<PacketBatch>,
    HashSet<ShredId>,
    HashSet<ShredId>,
) {
    let mut workload = Vec::with_capacity(num_slots * batches_per_slot);

    let expected_valid_capacity =
        num_slots * (batches_per_slot * PACKETS_PER_BATCH - invalid_packets_per_slot);
    let expected_invalid_capacity = num_slots * invalid_packets_per_slot;

    let mut expected_valid_ids =
        HashSet::<ShredId>::with_capacity(expected_valid_capacity);
    let mut expected_invalid_ids =
        HashSet::<ShredId>::with_capacity(expected_invalid_capacity);

    for slot_offset in 0..num_slots {
        let slot = FIRST_SLOT + slot_offset as u64;

        let (
            slot_batches,
            slot_expected_valid_ids,
            slot_expected_invalid_ids,
        ) = make_slot_batches(
            leader_keypair,
            slot,
            batches_per_slot,
            invalid_packets_per_slot,
        );

        workload.extend(slot_batches);

        for shred_id in slot_expected_valid_ids {
            assert!(
                !expected_invalid_ids.contains(&shred_id),
                "shred id appears as both valid and invalid: {shred_id:?}"
            );
            assert!(
                expected_valid_ids.insert(shred_id),
                "duplicate valid shred id across workload: {shred_id:?}"
            );
        }

        for shred_id in slot_expected_invalid_ids {
            assert!(
                !expected_valid_ids.contains(&shred_id),
                "shred id appears as both valid and invalid: {shred_id:?}"
            );
            assert!(
                expected_invalid_ids.insert(shred_id),
                "duplicate invalid shred id across workload: {shred_id:?}"
            );
        }
    }

    (
        workload,
        expected_valid_ids,
        expected_invalid_ids,
    )
}

/// Returns the target arrival time for `num_shreds` from the start of replay.
///
/// The replay rate is derived from the number of shreds per 400 ms slot.
fn arrival_offset(num_shreds: usize, shreds_per_slot: usize) -> Duration {
    let nanos = num_shreds as u128 * SLOT_DURATION.as_nanos() / shreds_per_slot as u128;

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
    let num_slots = env_usize("SHRED_SIGVERIFY_SLOTS", DEFAULT_NUM_SLOTS);

    let batches_per_slot = env_usize(
        "SHRED_SIGVERIFY_BATCHES_PER_SLOT",
        DEFAULT_BATCHES_PER_SLOT,
    );

    let invalid_packets_per_slot = env_usize(
        "SHRED_SIGVERIFY_INVALID_PACKETS_PER_SLOT",
        DEFAULT_INVALID_PACKETS_PER_SLOT,
    );

    let num_sigverify_threads = NonZeroUsize::new(env_usize(
        "SHRED_SIGVERIFY_THREADS",
        DEFAULT_NUM_SIGVERIFY_THREADS,
    ))
    .expect("SHRED_SIGVERIFY_THREADS must be greater than zero");

    assert!(num_slots > 0, "SHRED_SIGVERIFY_SLOTS must be greater than zero");
    assert!(
        batches_per_slot > 0,
        "SHRED_SIGVERIFY_BATCHES_PER_SLOT must be greater than zero"
    );

    let shreds_per_slot = batches_per_slot * PACKETS_PER_BATCH;

    assert!(
        invalid_packets_per_slot <= shreds_per_slot,
        "SHRED_SIGVERIFY_INVALID_PACKETS_PER_SLOT must not exceed packets per slot"
    );

    let expected_shreds = num_slots * shreds_per_slot;
    let expected_invalid_shreds = num_slots * invalid_packets_per_slot;
    let expected_valid_shreds = expected_shreds - expected_invalid_shreds;

    println!(
        "shred sigverify workload: \
         slots={num_slots}, \
         batches_per_slot={batches_per_slot}, \
         packets_per_batch={PACKETS_PER_BATCH}, \
         shreds_per_slot={shreds_per_slot}, \
         invalid_packets_per_slot={invalid_packets_per_slot}, \
         total_shreds={expected_shreds}, \
         intentionally_invalid={expected_invalid_shreds}, \
         sigverify_threads={num_sigverify_threads}"
    );

    let leader_keypair = Arc::new(Keypair::new());
    let leader_pubkey = leader_keypair.pubkey();

    // The validator running sigverify must not be the leader.
    let node_keypair = Arc::new(Keypair::new());
    let node_pubkey = node_keypair.pubkey();

    // Build the workload together with an exact oracle of which ShredIds
    // must survive and which intentionally corrupted ShredIds must not.
    let (
        workload,
        expected_valid_ids,
        expected_invalid_ids,
    ) = make_workload(
        leader_keypair.as_ref(),
        num_slots,
        batches_per_slot,
        invalid_packets_per_slot,
    );

    assert_eq!(workload.len(), num_slots * batches_per_slot);
    assert_eq!(
        workload.iter().map(PacketBatch::len).sum::<usize>(),
        expected_shreds,
    );
    assert_eq!(expected_valid_ids.len(), expected_valid_shreds);
    assert_eq!(expected_invalid_ids.len(), expected_invalid_shreds);
    assert_eq!(
        expected_valid_ids.len() + expected_invalid_ids.len(),
        expected_shreds
    );

    let bank = Bank::new_for_tests(
        &create_genesis_config_with_leader(100, &leader_pubkey, 10).genesis_config,
    );

    let leader_schedule_cache = Arc::new(LeaderScheduleCache::new_from_bank(&bank));
    let bank_forks = BankForks::new_rw_arc(bank);

    let cluster_info = Arc::new(ClusterInfo::new(
        ContactInfo::new_localhost(&node_pubkey, timestamp()),
        node_keypair,
        SocketAddrSpace::Unspecified,
    ));

    let (shred_fetch_sender, shred_fetch_receiver) =
        bounded::<PacketBatch>(CHANNEL_CAPACITY);

    // Retransmit consumption itself is outside this benchmark.
    let (retransmit_sender, _retransmit_receiver) = EvictingSender::new_bounded(1);

    // Drain verified output continuously so sigverify cannot block on the
    // downstream channel. Record every exact ShredId that reaches the output.
    let (verified_sender, verified_receiver) = bounded::<
        Vec<(
            solana_ledger::shred::Payload,
            bool,
            solana_ledger::blockstore_meta::BlockLocation,
        )>,
    >(CHANNEL_CAPACITY);

    let verified_handle = thread::spawn(move || {
        let mut verified_ids = HashSet::<ShredId>::new();

        for shreds in verified_receiver {
            for (payload, _is_repaired, _location) in shreds {
                let shred_id = shred::layout::get_shred_id(payload.as_ref())
                    .expect("verified output contains payload without a valid ShredId");

                assert!(
                    verified_ids.insert(shred_id),
                    "verified output contains duplicate shred id: {shred_id:?}"
                );
            }
        }

        verified_ids
    });

    let repair_nonce_location_lookup: Arc<RepairNonceLocationLookup> = Arc::new(|_| None);

    reset_sigverify_debug_counters();

    // Worker creation is outside the measured section.
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

    perf.enable();

    let replay_start = Instant::now();
    let mut sent_shreds = 0usize;

    for batch in workload {
        let deadline = replay_start + arrival_offset(sent_shreds, shreds_per_slot);

        sleep_until(deadline);

        let batch_len = batch.len();

        shred_fetch_sender
            .send(batch)
            .expect("shred sigverify receiver disconnected");

        sent_shreds += batch_len;
    }

    assert_eq!(sent_shreds, expected_shreds);

    // Closing ingress lets sigverify drain all queued batches and terminate.
    drop(shred_fetch_sender);

    sigverify_handle
        .join()
        .expect("shred sigverify thread panicked");

    let verified_ids = verified_handle
        .join()
        .expect("verified shred consumer panicked");

    let verified_shreds = verified_ids.len();
    let debug = sigverify_debug_counters();

    println!(
        "CRYPTO COUNTERS: \
         verify_calls={} \
         precrypto_rejects={} \
         cache_hits={} \
         crypto_calls={} \
         crypto_success={} \
         crypto_failed={}",
        debug.verify_calls,
        debug.precrypto_rejects,
        debug.cache_hits,
        debug.crypto_calls,
        debug.crypto_success,
        debug.crypto_failed,
    );

    perf.disable();

    assert_eq!(
        debug.verify_calls,
        debug.precrypto_rejects + debug.cache_hits + debug.crypto_calls,
        "verify-call accounting does not balance"
    );
    assert_eq!(
        debug.crypto_calls,
        debug.crypto_success + debug.crypto_failed,
        "crypto-call accounting does not balance"
    );

    let missing_valid_count = expected_valid_ids.difference(&verified_ids).count();

    let invalid_passed_count = expected_invalid_ids.intersection(&verified_ids).count();

    let unexpected_output_count = verified_ids
        .iter()
        .filter(|shred_id| {
            !expected_valid_ids.contains(shred_id)
                && !expected_invalid_ids.contains(shred_id)
        })
        .count();

    let missing_valid_sample: Vec<_> = expected_valid_ids
        .difference(&verified_ids)
        .take(10)
        .copied()
        .collect();

    let invalid_passed_sample: Vec<_> = expected_invalid_ids
        .intersection(&verified_ids)
        .take(10)
        .copied()
        .collect();

    let unexpected_output_sample: Vec<_> = verified_ids
        .iter()
        .filter(|shred_id| {
            !expected_valid_ids.contains(shred_id)
                && !expected_invalid_ids.contains(shred_id)
        })
        .take(10)
        .copied()
        .collect();

    println!(
        "EXACT OUTPUT CHECK: \
         expected_valid={} \
         expected_invalid={} \
         actual_verified={} \
         missing_valid={} \
         invalid_passed={} \
         unexpected_output={}",
        expected_valid_ids.len(),
        expected_invalid_ids.len(),
        verified_ids.len(),
        missing_valid_count,
        invalid_passed_count,
        unexpected_output_count,
    );

    println!(
        "shred sigverify result: \
         sent={sent_shreds}, \
         intentionally_invalid={expected_invalid_shreds}, \
         expected_valid={expected_valid_shreds}, \
         verified={verified_shreds}, \
         additional_discards={}",
        expected_valid_shreds.saturating_sub(verified_shreds),
    );

    assert_eq!(
        invalid_passed_count,
        0,
        "intentionally invalid shreds escaped sigverify: {invalid_passed_sample:?}"
    );

    assert_eq!(
        unexpected_output_count,
        0,
        "sigverify emitted shreds that were not in the input workload: \
         {unexpected_output_sample:?}"
    );

    assert_eq!(
        missing_valid_count,
        0,
        "valid input shreds were lost: {missing_valid_sample:?}"
    );

    assert_eq!(
        verified_ids,
        expected_valid_ids,
        "verified output ShredIds do not exactly match expected valid input ShredIds"
    );
}