use {
    crate::{
        cluster_nodes::{ClusterNodesCache, DATA_PLANE_FANOUT},
        retransmit_stage::RetransmitStage,
    },
    agave_feature_set as feature_set,
    crossbeam_channel::{Receiver, RecvTimeoutError, SendError, Sender, bounded},
    itertools::{Either, Itertools},
    solana_clock::Slot,
    solana_gossip::cluster_info::ClusterInfo,
    solana_keypair::Keypair,
    solana_ledger::{
        blockstore_meta::BlockLocation,
        leader_schedule_cache::LeaderScheduleCache,
        shred::{
            self,
            layout::{get_shred, get_shred_mut, set_retransmitter_signature},
            wire::is_retransmitter_signed_variant,
        },
        sigverify_shreds::{LruCache, SlotPubkeys, verify_shred_cpu},
    },
    solana_perf::{
        deduper::Deduper,
        packet::{PacketBatch, PacketRef, PacketRefMut},
    },
    solana_pubkey::Pubkey,
    solana_runtime::{bank::Bank, bank_forks::BankForks},
    solana_signature::Signature,
    solana_signer::Signer,
    solana_streamer::{evicting_sender::EvictingSender, streamer::ChannelSend},
    std::{
        num::NonZeroUsize,
        sync::{
            Arc, RwLock,
            atomic::{AtomicUsize, Ordering},
        },
        thread::{Builder, JoinHandle},
        time::{Duration, Instant},
    },
    thiserror::Error,
};

// 34MB where each cache entry is 136 bytes.
const SIGVERIFY_LRU_CACHE_CAPACITY: usize = 1 << 18;

const DEDUPER_FALSE_POSITIVE_RATE: f64 = 0.001;
const DEDUPER_NUM_BITS: u64 = 637_534_199; // 76MB
const DEDUPER_RESET_CYCLE: Duration = Duration::from_secs(5 * 60);

// Num epochs capacity should be at least 2 because near the epoch boundary we
// may receive shreds from the other side of the epoch boundary. Because of the
// TTL based eviction it is extremely unlikely that we will ever store > 2 epochs anyway
const CLUSTER_NODES_CACHE_NUM_EPOCH_CAP: usize = 2;
// Because for ClusterNodes::get_retransmit_parent only pubkeys of staked nodes
// are needed, we can use longer durations for cache TTL.
const CLUSTER_NODES_CACHE_TTL: Duration = Duration::from_secs(30);

/// Maximum number of packet batches to process in a single sigverify iteration.
const SIGVERIFY_SHRED_BATCH_SIZE: usize = 1024;

#[allow(clippy::enum_variant_names)]
enum ShredSigverifyError {
    RecvDisconnected,
    RecvTimeout,
    SendError,
}

#[derive(Debug, Error)]
enum ResignError {
    #[error("verification of retransmitter signature failed")]
    VerifyRetransmitterSignature,
    #[error(transparent)]
    Shred(#[from] shred::Error),
}

pub type RepairNonceLocationLookup = dyn Fn(shred::Nonce) -> Option<BlockLocation> + Send + Sync;

#[derive(Clone, Copy)]
struct PacketLocation {
    batch_index: usize,
    packet_index: usize,
}

struct VerifyJob {
    batches: Arc<Vec<PacketBatch>>,
    locations: Arc<Vec<PacketLocation>>,
    range: std::ops::Range<usize>,
    slot_leaders: Arc<SlotPubkeys>,
}

struct VerifyResult {
    invalid_locations: Vec<PacketLocation>,
}

struct ResignJob {
    batches: Arc<Vec<PacketBatch>>,
    locations: Arc<Vec<PacketLocation>>,
    range: std::ops::Range<usize>,
    root_bank: Arc<Bank>,
    working_bank: Arc<Bank>,
    keypair: Arc<Keypair>,
}

enum ResignAction {
    Discard(PacketLocation),
    SetSignature {
        location: PacketLocation,
        signature: Signature,
    },
}

#[derive(Default)]
struct ResignWorkerStats {
    num_invalid_retransmitter: usize,
    num_retranmitter_signature_skipped: usize,
    num_retranmitter_signature_verified: usize,
    num_unknown_slot_leader: usize,
    num_unknown_turbine_parent: usize,
}

struct ResignResult {
    actions: Vec<ResignAction>,
    stats: ResignWorkerStats,
}

enum VerifyWorkerMessage {
    Verify(VerifyJob),
    Resign(ResignJob),
    Shutdown,
}

enum VerifyWorkerResult {
    Verify(VerifyResult),
    Resign(ResignResult),
}

struct VerifyWorker {
    job_sender: Sender<VerifyWorkerMessage>,
    result_receiver: Receiver<VerifyWorkerResult>,
    handle: Option<JoinHandle<()>>,
}

struct ShredSigverifyWorkers {
    workers: Vec<VerifyWorker>,
}

impl ShredSigverifyWorkers {
    fn new(
        num_workers: NonZeroUsize,
        cache: Arc<RwLock<LruCache>>,
        cluster_info: Arc<ClusterInfo>,
        leader_schedule_cache: Arc<LeaderScheduleCache>,
        cluster_nodes_cache: Arc<ClusterNodesCache<RetransmitStage>>,
    ) -> Self {
        let workers = (0..num_workers.get())
            .map(|index| {
                let (job_sender, job_receiver) = bounded::<VerifyWorkerMessage>(1);
                let (result_sender, result_receiver) = bounded::<VerifyWorkerResult>(1);

                let cache = cache.clone();
                let cluster_info = cluster_info.clone();
                let leader_schedule_cache = leader_schedule_cache.clone();
                let cluster_nodes_cache = cluster_nodes_cache.clone();

                let handle = Builder::new()
                    .name(format!("solSvrfyShred{index:02}"))
                    .spawn(move || {
                        while let Ok(message) = job_receiver.recv() {
                            let result = match message {
                                VerifyWorkerMessage::Verify(job) => {
                                    let VerifyJob {
                                        batches,
                                        locations,
                                        range,
                                        slot_leaders,
                                    } = job;

                                    let mut invalid_locations = Vec::new();

                                    for &location in &locations[range] {
                                        let packet = batches[location.batch_index]
                                            .get(location.packet_index)
                                            .expect(
                                                "packet location must reference an existing packet",
                                            );

                                        if !verify_shred_cpu(
                                            packet,
                                            slot_leaders.as_ref(),
                                            cache.as_ref(),
                                        ) {
                                            invalid_locations.push(location);
                                        }
                                    }

                                    VerifyWorkerResult::Verify(VerifyResult { invalid_locations })
                                }

                                VerifyWorkerMessage::Resign(job) => {
                                    let ResignJob {
                                        batches,
                                        locations,
                                        range,
                                        root_bank,
                                        working_bank,
                                        keypair,
                                    } = job;

                                    let mut actions = Vec::new();
                                    let mut stats = ResignWorkerStats::default();

                                    for &location in &locations[range] {
                                        let packet = batches[location.batch_index]
                                            .get(location.packet_index)
                                            .expect(
                                                "packet location must reference an existing packet",
                                            );

                                        match maybe_verify_and_prepare_resign(
                                            packet,
                                            root_bank.as_ref(),
                                            working_bank.as_ref(),
                                            cluster_info.as_ref(),
                                            leader_schedule_cache.as_ref(),
                                            cluster_nodes_cache.as_ref(),
                                            &mut stats,
                                            keypair.as_ref(),
                                        ) {
                                            Ok(Some(signature)) => {
                                                actions.push(ResignAction::SetSignature {
                                                    location,
                                                    signature,
                                                });
                                            }
                                            Ok(None) => {}
                                            Err(_) => {
                                                actions.push(ResignAction::Discard(location));
                                            }
                                        }
                                    }

                                    VerifyWorkerResult::Resign(ResignResult { actions, stats })
                                }

                                VerifyWorkerMessage::Shutdown => break,
                            };

                            if result_sender.send(result).is_err() {
                                break;
                            }
                        }
                    })
                    .unwrap();

                VerifyWorker {
                    job_sender,
                    result_receiver,
                    handle: Some(handle),
                }
            })
            .collect();

        Self { workers }
    }
}

impl Drop for ShredSigverifyWorkers {
    fn drop(&mut self) {
        for worker in &self.workers {
            let _ = worker.job_sender.send(VerifyWorkerMessage::Shutdown);
        }

        for worker in &mut self.workers {
            if let Some(handle) = worker.handle.take() {
                let _ = handle.join();
            }
        }
    }
}

pub fn spawn_shred_sigverify(
    cluster_info: Arc<ClusterInfo>,
    bank_forks: Arc<RwLock<BankForks>>,
    leader_schedule_cache: Arc<LeaderScheduleCache>,
    shred_fetch_receiver: Receiver<PacketBatch>,
    retransmit_sender: EvictingSender<Vec<shred::Payload>>,
    verified_sender: Sender<Vec<(shred::Payload, /*is_repaired:*/ bool, BlockLocation)>>,
    repair_nonce_location_lookup: Arc<RepairNonceLocationLookup>,
    num_sigverify_threads: NonZeroUsize,
) -> JoinHandle<()> {
    let mut stats = ShredSigVerifyStats::new(Instant::now());

    let cache = Arc::new(RwLock::new(LruCache::new(SIGVERIFY_LRU_CACHE_CAPACITY)));

    let cluster_nodes_cache = Arc::new(ClusterNodesCache::<RetransmitStage>::new(
        CLUSTER_NODES_CACHE_NUM_EPOCH_CAP,
        CLUSTER_NODES_CACHE_TTL,
    ));

    let workers = ShredSigverifyWorkers::new(
        num_sigverify_threads,
        cache,
        cluster_info.clone(),
        leader_schedule_cache.clone(),
        cluster_nodes_cache,
    );

    let run_shred_sigverify = move || {
        let mut rng = rand::rng();
        let deduper = Deduper::<2, [u8]>::new(&mut rng, DEDUPER_NUM_BITS);
        let mut shred_buffer = Vec::with_capacity(SIGVERIFY_SHRED_BATCH_SIZE);

        loop {
            if deduper.maybe_reset(&mut rng, DEDUPER_FALSE_POSITIVE_RATE, DEDUPER_RESET_CYCLE) {
                stats.num_deduper_saturations += 1;
            }

            // We can't store the keypair outside the loop
            // because the identity might be hot swapped.
            let keypair = cluster_info.keypair();

            match run_shred_sigverify(
                &workers,
                &keypair,
                &bank_forks,
                &leader_schedule_cache,
                &deduper,
                &shred_fetch_receiver,
                &retransmit_sender,
                &verified_sender,
                repair_nonce_location_lookup.as_ref(),
                &mut stats,
                &mut shred_buffer,
            ) {
                Ok(()) => (),
                Err(ShredSigverifyError::RecvTimeout) => (),
                Err(ShredSigverifyError::RecvDisconnected) => break,
                Err(ShredSigverifyError::SendError) => break,
            }

            stats.maybe_submit();
        }
    };

    Builder::new()
        .name("solShredVerifr".to_string())
        .spawn(run_shred_sigverify)
        .unwrap()
}

#[allow(clippy::too_many_arguments)]
fn run_shred_sigverify<const K: usize>(
    workers: &ShredSigverifyWorkers,
    keypair: &Arc<Keypair>,
    bank_forks: &RwLock<BankForks>,
    leader_schedule_cache: &LeaderScheduleCache,
    deduper: &Deduper<K, [u8]>,
    shred_fetch_receiver: &Receiver<PacketBatch>,
    retransmit_sender: &EvictingSender<Vec<shred::Payload>>,
    verified_sender: &Sender<Vec<(shred::Payload, /*is_repaired:*/ bool, BlockLocation)>>,
    repair_nonce_location_lookup: &RepairNonceLocationLookup,
    stats: &mut ShredSigVerifyStats,
    shred_buffer: &mut Vec<PacketBatch>,
) -> Result<(), ShredSigverifyError> {
    const RECV_TIMEOUT: Duration = Duration::from_secs(1);

    let packets = shred_fetch_receiver.recv_timeout(RECV_TIMEOUT)?;
    stats.num_packets += packets.len();
    shred_buffer.push(packets);

    for packets in shred_fetch_receiver
        .try_iter()
        .take(SIGVERIFY_SHRED_BATCH_SIZE - 1)
    {
        stats.num_packets += packets.len();
        shred_buffer.push(packets);
    }

    let now = Instant::now();
    stats.num_iters += 1;
    stats.num_batches += shred_buffer.len();
    stats.num_discards_pre += count_discards(shred_buffer);

    // Repair shreds include a randomly generated u32 nonce, so it does not
    // make sense to deduplicate the entire packet payload (i.e. they are not
    // duplicate of any other packet.data(..)).
    // If the nonce is excluded from the deduper then false positives might
    // prevent us from repairing a block until the deduper is reset after
    // DEDUPER_RESET_CYCLE. A workaround is to also repair "coding" shreds to
    // add some redundancy but that is not implemented at the moment.
    // Because the repair nonce is already verified in shred-fetch-stage we can
    // exclude repair shreds from the deduper, but we still need to pass the
    // repair shred to the deduper to filter out duplicates from the turbine
    // path once a shred is repaired.
    // For backward compatibility we need to allow trailing bytes in the packet
    // after the shred payload, but have to exclude them here from the deduper.
    stats.num_duplicates += shred_buffer
        .iter_mut()
        .flatten()
        .filter(|packet| {
            !packet.meta().discard()
                && shred::wire::get_shred(packet.as_ref())
                    .map(|shred| deduper.dedup(shred))
                    .unwrap_or(true)
                && !packet.meta().repair()
        })
        .map(|mut packet| packet.meta_mut().set_discard(true))
        .count();

    let (working_bank, root_bank) = {
        let bank_forks = bank_forks.read().unwrap();
        (bank_forks.working_bank(), bank_forks.root_bank())
    };

    verify_packets(
        workers,
        &keypair.pubkey(),
        &working_bank,
        leader_schedule_cache,
        shred_buffer,
    );

    stats.num_discards_post += count_discards(shred_buffer);

    // Verify retransmitter signatures and calculate new retransmitter
    // signatures in the persistent worker threads. The coordinator applies
    // the resulting mutations after all workers complete.
    let resign_start = Instant::now();

    resign_packets(
        workers,
        shred_buffer,
        root_bank,
        working_bank,
        keypair.clone(),
        stats,
    );

    stats.resign_micros += resign_start.elapsed().as_micros() as u64;

    // Extract shred payload from packets, and separate out repaired shreds.
    let (shreds, repairs): (Vec<_>, Vec<_>) = shred_buffer
        .iter()
        .flat_map(|batch| batch.iter())
        .filter(|packet| !packet.meta().discard())
        .filter_map(|packet| {
            extract_shred_and_location(packet, repair_nonce_location_lookup, stats)
        })
        .partition_map(|(shred, location)| {
            if let Some(location) = location {
                // No need for Arc overhead here because repaired shreds are
                // not retransmitted.
                Either::Right((
                    shred::Payload::from(shred),
                    /* is_repaired */ true,
                    location,
                ))
            } else {
                // Share the payload between the retransmit-stage and the
                // window-service.
                Either::Left(shred::Payload::from(shred))
            }
        });

    // Repaired shreds are not retransmitted.
    stats.num_retransmit_shreds += shreds.len();

    if let Err(send_err) = retransmit_sender.try_send(shreds.clone()) {
        match send_err {
            crossbeam_channel::TrySendError::Full(v) => {
                stats.num_retransmit_stage_overflow_shreds += v.len();
            }
            _ => unreachable!("EvictingSender holds on to both ends of the channel"),
        }
    }

    // Send all shreds to window service to be inserted into blockstore.
    let shreds = shreds
        .into_iter()
        .map(|shred| (shred, /*is_repaired:*/ false, BlockLocation::Original));

    verified_sender.send(shreds.chain(repairs).collect())?;

    stats.elapsed_micros += now.elapsed().as_micros() as u64;
    shred_buffer.clear();

    Ok(())
}
/// Extracts shred bytes and, for repaired shreds, the location where the shred
/// should be inserted into blockstore.
fn extract_shred_and_location(
    packet: PacketRef,
    repair_nonce_location_lookup: &RepairNonceLocationLookup,
    stats: &mut ShredSigVerifyStats,
) -> Option<(Vec<u8>, Option<BlockLocation>)> {
    let (shred, nonce) = shred::layout::get_shred_and_repair_nonce(packet)?;
    let Some(nonce) = nonce else {
        // Turbine shred.
        return Some((shred.to_vec(), None));
    };

    // Repair shred.
    if let Some(location) = repair_nonce_location_lookup(nonce) {
        Some((shred.to_vec(), Some(location)))
    } else {
        // This indicates the request entry was evicted before consumption.
        stats.num_unknown_block_location += 1;
        None
    }
}

#[allow(clippy::too_many_arguments)]
fn maybe_verify_and_prepare_resign(
    packet: PacketRef,
    root_bank: &Bank,
    working_bank: &Bank,
    cluster_info: &ClusterInfo,
    leader_schedule_cache: &LeaderScheduleCache,
    cluster_nodes_cache: &ClusterNodesCache<RetransmitStage>,
    stats: &mut ResignWorkerStats,
    keypair: &Keypair,
) -> Result<Option<Signature>, ResignError> {
    let repair = packet.meta().repair();
    let shred = get_shred(packet).ok_or(shred::Error::InvalidPacketSize)?;

    if !is_retransmitter_signed_variant(shred)? {
        return Ok(None);
    }

    if !repair
        && !verify_retransmitter_signature(
            shred,
            root_bank,
            working_bank,
            cluster_info,
            leader_schedule_cache,
            cluster_nodes_cache,
            stats,
        )
    {
        stats.num_invalid_retransmitter += 1;

        if shred::layout::get_slot(shred)
            .map(|slot| {
                shred::filter::check_feature_activation_from_bank(
                    &feature_set::verify_retransmitter_signature::id(),
                    slot,
                    root_bank,
                )
            })
            .unwrap_or_default()
        {
            return Err(ResignError::VerifyRetransmitterSignature);
        }
    }

    let merkle_root =
        shred::layout::get_merkle_root(shred).ok_or(shred::Error::InvalidMerkleRoot)?;

    Ok(Some(keypair.sign_message(merkle_root.as_ref())))
}

#[must_use]
fn verify_retransmitter_signature(
    shred: &[u8],
    root_bank: &Bank,
    working_bank: &Bank,
    cluster_info: &ClusterInfo,
    leader_schedule_cache: &LeaderScheduleCache,
    cluster_nodes_cache: &ClusterNodesCache<RetransmitStage>,
    stats: &mut ResignWorkerStats,
) -> bool {
    let signature = match shred::layout::get_retransmitter_signature(shred) {
        Ok(signature) => signature,
        Err(shred::Error::InvalidShredVariant) => return true,
        Err(_) => return false,
    };

    let Some(merkle_root) = shred::layout::get_merkle_root(shred) else {
        return false;
    };

    let Some(shred) = shred::layout::get_shred_id(shred) else {
        return false;
    };

    let Some(leader) = leader_schedule_cache.slot_leader_at(shred.slot(), Some(working_bank))
    else {
        stats.num_unknown_slot_leader += 1;
        return false;
    };

    let cluster_nodes =
        cluster_nodes_cache.get(shred.slot(), root_bank, working_bank, cluster_info);

    let parent = match cluster_nodes.get_retransmit_parent(&leader.id, &shred, DATA_PLANE_FANOUT) {
        Ok(Some(parent)) => parent,
        Ok(None) => {
            stats.num_retranmitter_signature_skipped += 1;
            return true;
        }
        Err(err) => {
            error!("get_retransmit_parent: {err:?}");
            stats.num_unknown_turbine_parent += 1;
            return false;
        }
    };

    if signature.verify(parent.as_ref(), merkle_root.as_ref()) {
        stats.num_retranmitter_signature_verified += 1;
        true
    } else {
        false
    }
}

fn apply_retransmitter_signature(
    packet: &mut PacketRefMut,
    signature: &Signature,
) -> Result<(), shred::Error> {
    match packet {
        PacketRefMut::Packet(packet) => {
            let shred =
                get_shred_mut(packet.buffer_mut()).ok_or(shred::Error::InvalidPacketSize)?;

            set_retransmitter_signature(shred, signature)
        }
        PacketRefMut::Bytes(packet) => {
            let mut buffer = packet.buffer().to_vec();

            let shred = get_shred_mut(&mut buffer).ok_or(shred::Error::InvalidPacketSize)?;

            set_retransmitter_signature(shred, signature)?;

            packet.set_buffer(buffer);

            Ok(())
        }
    }
}
fn resign_packets(
    workers: &ShredSigverifyWorkers,
    packets: &mut Vec<PacketBatch>,
    root_bank: Arc<Bank>,
    working_bank: Arc<Bank>,
    keypair: Arc<Keypair>,
    stats: &ShredSigVerifyStats,
) {
    let locations = Arc::new(
        packets
            .iter()
            .enumerate()
            .flat_map(|(batch_index, batch)| {
                batch
                    .iter()
                    .enumerate()
                    .filter(|(_, packet)| !packet.meta().discard())
                    .map(move |(packet_index, _)| PacketLocation {
                        batch_index,
                        packet_index,
                    })
            })
            .collect::<Vec<_>>(),
    );

    if locations.is_empty() {
        return;
    }

    let num_workers = workers.workers.len().min(locations.len());
    let base_work = locations.len() / num_workers;
    let extra_work = locations.len() % num_workers;

    let shared_batches = Arc::new(std::mem::take(packets));

    let mut start = 0;

    for (worker_index, worker) in workers.workers.iter().take(num_workers).enumerate() {
        let work_len = base_work + usize::from(worker_index < extra_work);
        let end = start + work_len;

        worker
            .job_sender
            .send(VerifyWorkerMessage::Resign(ResignJob {
                batches: shared_batches.clone(),
                locations: locations.clone(),
                range: start..end,
                root_bank: root_bank.clone(),
                working_bank: working_bank.clone(),
                keypair: keypair.clone(),
            }))
            .expect("shred sigverify worker must be alive");

        start = end;
    }

    debug_assert_eq!(start, locations.len());

    let mut actions = Vec::new();

    for worker in workers.workers.iter().take(num_workers) {
        let VerifyWorkerResult::Resign(result) = worker
            .result_receiver
            .recv()
            .expect("shred sigverify worker must return a result")
        else {
            unreachable!("sigverify worker returned unexpected result");
        };

        stats
            .num_invalid_retransmitter
            .fetch_add(result.stats.num_invalid_retransmitter, Ordering::Relaxed);

        stats.num_retranmitter_signature_skipped.fetch_add(
            result.stats.num_retranmitter_signature_skipped,
            Ordering::Relaxed,
        );

        stats.num_retranmitter_signature_verified.fetch_add(
            result.stats.num_retranmitter_signature_verified,
            Ordering::Relaxed,
        );

        stats
            .num_unknown_slot_leader
            .fetch_add(result.stats.num_unknown_slot_leader, Ordering::Relaxed);

        stats
            .num_unknown_turbine_parent
            .fetch_add(result.stats.num_unknown_turbine_parent, Ordering::Relaxed);

        actions.extend(result.actions);
    }

    let mut batches = Arc::try_unwrap(shared_batches)
        .expect("shred sigverify workers must release packet batches");

    for action in actions {
        match action {
            ResignAction::Discard(location) => {
                let mut packet = batches[location.batch_index]
                    .get_mut(location.packet_index)
                    .expect("packet location must reference an existing packet");

                packet.meta_mut().set_discard(true);
            }
            ResignAction::SetSignature {
                location,
                signature,
            } => {
                let mut packet = batches[location.batch_index]
                    .get_mut(location.packet_index)
                    .expect("packet location must reference an existing packet");

                if apply_retransmitter_signature(&mut packet, &signature).is_err() {
                    packet.meta_mut().set_discard(true);
                }
            }
        }
    }

    *packets = batches;
}

fn verify_packets(
    workers: &ShredSigverifyWorkers,
    self_pubkey: &Pubkey,
    working_bank: &Bank,
    leader_schedule_cache: &LeaderScheduleCache,
    packets: &mut Vec<PacketBatch>,
) {
    let leader_slots = Arc::new(
        get_slot_leaders(self_pubkey, packets, leader_schedule_cache, working_bank)
            .filter_map(|(slot, pubkey)| Some((slot, pubkey?)))
            .chain(std::iter::once((Slot::MAX, Pubkey::default())))
            .collect::<SlotPubkeys>(),
    );

    let locations = Arc::new(
        packets
            .iter()
            .enumerate()
            .flat_map(|(batch_index, batch)| {
                batch
                    .iter()
                    .enumerate()
                    .filter(|(_, packet)| !packet.meta().discard())
                    .map(move |(packet_index, _)| PacketLocation {
                        batch_index,
                        packet_index,
                    })
            })
            .collect::<Vec<_>>(),
    );

    if locations.is_empty() {
        return;
    }

    let num_workers = workers.workers.len().min(locations.len());
    let base_work = locations.len() / num_workers;
    let extra_work = locations.len() % num_workers;

    let shared_batches = Arc::new(std::mem::take(packets));

    let mut start = 0;

    for (worker_index, worker) in workers.workers.iter().take(num_workers).enumerate() {
        let work_len = base_work + usize::from(worker_index < extra_work);
        let end = start + work_len;

        worker
            .job_sender
            .send(VerifyWorkerMessage::Verify(VerifyJob {
                batches: shared_batches.clone(),
                locations: locations.clone(),
                range: start..end,
                slot_leaders: leader_slots.clone(),
            }))
            .expect("shred sigverify worker must be alive");

        start = end;
    }

    debug_assert_eq!(start, locations.len());

    let mut invalid_locations = Vec::new();

    for worker in workers.workers.iter().take(num_workers) {
        let VerifyWorkerResult::Verify(result) = worker
            .result_receiver
            .recv()
            .expect("shred sigverify worker must return a result")
        else {
            unreachable!("sigverify worker returned unexpected result");
        };

        invalid_locations.extend(result.invalid_locations);
    }

    let mut batches = Arc::try_unwrap(shared_batches)
        .expect("shred sigverify workers must release packet batches");

    for location in invalid_locations {
        let mut packet = batches[location.batch_index]
            .get_mut(location.packet_index)
            .expect("packet location must reference an existing packet");

        packet.meta_mut().set_discard(true);
    }

    *packets = batches;
}

// Returns pubkey of leaders for shred slots referenced in the packets.
// Marks packets as discard if:
//   - fails to deserialize the shred slot.
//   - slot leader is unknown.
//   - slot leader is the node itself (circular transmission).
fn get_slot_leaders<'a>(
    self_pubkey: &'a Pubkey,
    batches: &'a mut [PacketBatch],
    leader_schedule_cache: &'a LeaderScheduleCache,
    bank: &'a Bank,
) -> impl Iterator<Item = (Slot, Option<Pubkey>)> + 'a {
    batches
        .iter_mut()
        .flat_map(|batch| batch.iter_mut())
        .filter(|packet| !packet.meta().discard())
        .filter_map(move |mut packet| {
            let shred = shred::layout::get_shred(packet.as_ref());
            let slot = shred.and_then(shred::layout::get_slot)?;
            let leader = leader_schedule_cache
                .slot_leader_at(slot, Some(bank))
                .map(|leader| leader.id)
                .filter(|leader| leader != self_pubkey);
            if leader.is_none() {
                packet.meta_mut().set_discard(true);
            }
            Some((slot, leader))
        })
}

fn count_discards(packets: &[PacketBatch]) -> usize {
    packets
        .iter()
        .flat_map(|batch| batch.iter())
        .filter(|packet| packet.meta().discard())
        .count()
}

impl From<RecvTimeoutError> for ShredSigverifyError {
    fn from(err: RecvTimeoutError) -> Self {
        match err {
            RecvTimeoutError::Timeout => Self::RecvTimeout,
            RecvTimeoutError::Disconnected => Self::RecvDisconnected,
        }
    }
}

impl<T> From<SendError<T>> for ShredSigverifyError {
    fn from(_: SendError<T>) -> Self {
        Self::SendError
    }
}

struct ShredSigVerifyStats {
    since: Instant,
    num_iters: usize,
    num_batches: usize,
    num_packets: usize,
    num_deduper_saturations: usize,
    num_discards_post: usize,
    num_discards_pre: usize,
    num_duplicates: usize,
    num_invalid_retransmitter: AtomicUsize,
    num_retranmitter_signature_skipped: AtomicUsize,
    num_retranmitter_signature_verified: AtomicUsize,
    num_retransmit_stage_overflow_shreds: usize,
    num_retransmit_shreds: usize,
    /// This means the OutstandingRequests cache is saturated and we
    /// threw away a verified shred due to being unable to fetch the storage location
    num_unknown_block_location: usize,
    num_unknown_slot_leader: AtomicUsize,
    num_unknown_turbine_parent: AtomicUsize,
    elapsed_micros: u64,
    resign_micros: u64,
}

impl ShredSigVerifyStats {
    const METRICS_SUBMIT_CADENCE: Duration = Duration::from_secs(2);

    fn new(now: Instant) -> Self {
        Self {
            since: now,
            num_iters: 0usize,
            num_batches: 0usize,
            num_packets: 0usize,
            num_discards_pre: 0usize,
            num_deduper_saturations: 0usize,
            num_discards_post: 0usize,
            num_duplicates: 0usize,
            num_invalid_retransmitter: AtomicUsize::default(),
            num_retranmitter_signature_skipped: AtomicUsize::default(),
            num_retranmitter_signature_verified: AtomicUsize::default(),
            num_retransmit_stage_overflow_shreds: 0usize,
            num_retransmit_shreds: 0usize,
            num_unknown_block_location: 0usize,
            num_unknown_slot_leader: AtomicUsize::default(),
            num_unknown_turbine_parent: AtomicUsize::default(),
            elapsed_micros: 0u64,
            resign_micros: 0u64,
        }
    }

    fn maybe_submit(&mut self) {
        if self.since.elapsed() <= Self::METRICS_SUBMIT_CADENCE {
            return;
        }
        datapoint_info!(
            "shred_sigverify",
            ("num_iters", self.num_iters, i64),
            ("num_batches", self.num_batches, i64),
            ("num_packets", self.num_packets, i64),
            ("num_discards_pre", self.num_discards_pre, i64),
            ("num_deduper_saturations", self.num_deduper_saturations, i64),
            ("num_discards_post", self.num_discards_post, i64),
            ("num_duplicates", self.num_duplicates, i64),
            (
                "num_invalid_retransmitter",
                self.num_invalid_retransmitter.load(Ordering::Relaxed),
                i64
            ),
            (
                "num_retranmitter_signature_skipped",
                self.num_retranmitter_signature_skipped
                    .load(Ordering::Relaxed),
                i64
            ),
            (
                "num_retranmitter_signature_verified",
                self.num_retranmitter_signature_verified
                    .load(Ordering::Relaxed),
                i64
            ),
            (
                "num_retransmit_stage_overflow_shreds",
                self.num_retransmit_stage_overflow_shreds,
                i64
            ),
            ("num_retransmit_shreds", self.num_retransmit_shreds, i64),
            (
                "num_unknown_block_location",
                self.num_unknown_block_location,
                i64
            ),
            (
                "num_unknown_slot_leader",
                self.num_unknown_slot_leader.load(Ordering::Relaxed),
                i64
            ),
            (
                "num_unknown_turbine_parent",
                self.num_unknown_turbine_parent.load(Ordering::Relaxed),
                i64
            ),
            ("elapsed_micros", self.elapsed_micros, i64),
            ("resign_micros", self.resign_micros, i64),
        );
        *self = Self::new(Instant::now());
    }
}
#[cfg(test)]
mod tests {
    use {
        super::*,
        rand::Rng,
        solana_entry::entry::{Entry, create_ticks},
        solana_gossip::contact_info::ContactInfo,
        solana_hash::Hash,
        solana_keypair::Keypair,
        solana_ledger::{
            genesis_utils::create_genesis_config_with_leader,
            shred::{Nonce, ProcessShredsStats, ReedSolomonCache, Shredder},
        },
        solana_net_utils::SocketAddrSpace,
        solana_perf::packet::{Packet, PacketFlags, RecycledPacketBatch},
        solana_runtime::bank::Bank,
        solana_signer::Signer,
        solana_time_utils::timestamp,
        test_case::test_matrix,
    };

    fn new_sigverify_workers(
        cluster_info: Arc<ClusterInfo>,
        leader_schedule_cache: Arc<LeaderScheduleCache>,
        num_workers: usize,
    ) -> ShredSigverifyWorkers {
        let cache = Arc::new(RwLock::new(LruCache::new(/*capacity:*/ 128)));

        let cluster_nodes_cache = Arc::new(ClusterNodesCache::<RetransmitStage>::new(
            CLUSTER_NODES_CACHE_NUM_EPOCH_CAP,
            CLUSTER_NODES_CACHE_TTL,
        ));

        ShredSigverifyWorkers::new(
            NonZeroUsize::new(num_workers).unwrap(),
            cache,
            cluster_info,
            leader_schedule_cache,
            cluster_nodes_cache,
        )
    }

    #[test]
    fn test_sigverify_shreds_verify_batches() {
        let leader_keypair = Arc::new(Keypair::new());
        let wrong_keypair = Keypair::new();
        let leader_pubkey = leader_keypair.pubkey();

        let bank = Bank::new_for_tests(
            &create_genesis_config_with_leader(100, &leader_pubkey, 10).genesis_config,
        );

        let leader_schedule_cache = Arc::new(LeaderScheduleCache::new_from_bank(&bank));

        let bank_forks = BankForks::new_rw_arc(bank);

        let cluster_info = Arc::new(ClusterInfo::new(
            ContactInfo::new_localhost(&leader_pubkey, timestamp()),
            leader_keypair.clone(),
            SocketAddrSpace::Unspecified,
        ));

        let workers = new_sigverify_workers(cluster_info, leader_schedule_cache.clone(), 3);

        let batch_size = 2;
        let mut batch = RecycledPacketBatch::with_capacity(batch_size);
        batch.resize(batch_size, Packet::default());

        let mut batches = vec![batch];

        let entries = create_ticks(1, 1, Hash::new_unique());
        let shredder = Shredder::new(1, 0, 1, 0).unwrap();

        let (shreds_data, _shreds_code) = shredder.entries_to_merkle_shreds_for_tests(
            &leader_keypair,
            &entries,
            true,
            Hash::new_unique(),
            0,
            0,
            &ReedSolomonCache::default(),
            &mut ProcessShredsStats::default(),
        );

        let (shreds_data_wrong, _shreds_code_wrong) = shredder.entries_to_merkle_shreds_for_tests(
            &wrong_keypair,
            &entries,
            true,
            Hash::new_unique(),
            0,
            0,
            &ReedSolomonCache::default(),
            &mut ProcessShredsStats::default(),
        );

        let shred = shreds_data[0].clone();
        batches[0][0].buffer_mut()[..shred.payload().len()].copy_from_slice(shred.payload());
        batches[0][0].meta_mut().size = shred.payload().len();

        let shred = shreds_data_wrong[0].clone();
        batches[0][1].buffer_mut()[..shred.payload().len()].copy_from_slice(shred.payload());
        batches[0][1].meta_mut().size = shred.payload().len();

        let working_bank = bank_forks.read().unwrap().working_bank();

        let mut batches = batches
            .into_iter()
            .map(PacketBatch::from)
            .collect::<Vec<_>>();

        verify_packets(
            &workers,
            &Pubkey::new_unique(), // self_pubkey
            &working_bank,
            leader_schedule_cache.as_ref(),
            &mut batches,
        );

        // Correctly signed leader shred survives.
        assert!(!batches[0].get(0).unwrap().meta().discard());

        // Shred signed by the wrong leader is discarded.
        assert!(batches[0].get(1).unwrap().meta().discard());
    }

    #[test_matrix(
        [true, false],
        [true, false]
    )]
    fn test_resign_packets(repaired: bool, is_last_in_slot: bool) {
        let mut rng = rand::rng();

        let leader_keypair = Arc::new(Keypair::new());
        let leader_pubkey = leader_keypair.pubkey();

        let bank = Bank::new_for_tests(
            &create_genesis_config_with_leader(100, &leader_pubkey, 10).genesis_config,
        );

        let leader_schedule_cache = Arc::new(LeaderScheduleCache::new_from_bank(&bank));

        let bank_forks = BankForks::new_rw_arc(bank);

        let (working_bank, root_bank) = {
            let bank_forks = bank_forks.read().unwrap();
            (bank_forks.working_bank(), bank_forks.root_bank())
        };

        let cluster_info = Arc::new(ClusterInfo::new(
            ContactInfo::new_localhost(&leader_pubkey, timestamp()),
            leader_keypair.clone(),
            SocketAddrSpace::Unspecified,
        ));

        // Keep the same persistent worker pool for every shred in the test.
        let workers = new_sigverify_workers(cluster_info, leader_schedule_cache, 3);

        let chained_merkle_root = Hash::new_from_array(rng.random());

        let shredder = Shredder::new(root_bank.slot(), root_bank.parent_slot(), 0, 0).unwrap();

        let entries = vec![Entry::new(&Hash::default(), 0, vec![])];

        let mut shreds: Vec<_> = shredder
            .make_merkle_shreds_from_entries(
                &leader_keypair,
                &entries,
                is_last_in_slot,
                chained_merkle_root,
                0,
                0,
                &ReedSolomonCache::default(),
                &mut ProcessShredsStats::default(),
            )
            .collect();

        let stats = ShredSigVerifyStats::new(Instant::now());

        for shred in shreds.iter_mut() {
            let retransmitter_keypair = Arc::new(Keypair::new());
            let nonce = repaired.then(|| rng.random::<Nonce>());

            // Packet variant.
            let mut packet = shred.payload().to_packet(nonce);

            if repaired {
                packet.meta_mut().flags |= PacketFlags::REPAIR;
            }

            let mut packet_batch = RecycledPacketBatch::with_capacity(1);
            packet_batch.push(packet);

            // BytesPacket variant.
            let mut bytes_packet = shred.payload().to_bytes_packet(nonce);

            if repaired {
                bytes_packet.meta_mut().flags |= PacketFlags::REPAIR;
            }

            let bytes_buffer_address_before = bytes_packet.buffer().as_ptr().addr();

            let mut batches = vec![
                PacketBatch::from(packet_batch),
                PacketBatch::Single(bytes_packet),
            ];

            let packet_buffer_before = batches[0].get(0).unwrap().data(..).unwrap().to_vec();

            resign_packets(
                &workers,
                &mut batches,
                root_bank.clone(),
                working_bank.clone(),
                retransmitter_keypair.clone(),
                &stats,
            );

            let packet = batches[0].get(0).unwrap();
            let bytes_packet = batches[1].get(0).unwrap();

            assert!(!packet.meta().discard());
            assert!(!bytes_packet.meta().discard());

            let packet_buffer_after = packet.data(..).unwrap();

            let bytes_buffer_address_after = match &batches[1] {
                PacketBatch::Single(packet) => packet.buffer().as_ptr().addr(),
                _ => unreachable!("expected PacketBatch::Single"),
            };

            if is_last_in_slot {
                // Resigned variant: both packet representations must be modified.
                assert_ne!(packet_buffer_before.as_slice(), packet_buffer_after);
                assert_ne!(bytes_buffer_address_before, bytes_buffer_address_after);

                // More importantly, verify that the new retransmitter
                // signature is actually valid for the supplied keypair.
                for batch in &batches {
                    let packet = batch.get(0).unwrap();
                    let shred = get_shred(packet).unwrap();

                    let signature = shred::layout::get_retransmitter_signature(shred).unwrap();

                    let merkle_root = shred::layout::get_merkle_root(shred).unwrap();

                    assert!(signature.verify(
                        retransmitter_keypair.pubkey().as_ref(),
                        merkle_root.as_ref(),
                    ));
                }
            } else {
                // Non-resigned variant must remain untouched.
                assert_eq!(packet_buffer_before.as_slice(), packet_buffer_after);
                assert_eq!(bytes_buffer_address_before, bytes_buffer_address_after);
            }
        }
    }

    #[test]
    fn test_sigverify_workers_are_reused_across_rounds() {
        let leader_keypair = Arc::new(Keypair::new());
        let wrong_keypair = Keypair::new();
        let leader_pubkey = leader_keypair.pubkey();

        let bank = Bank::new_for_tests(
            &create_genesis_config_with_leader(100, &leader_pubkey, 10).genesis_config,
        );

        let leader_schedule_cache = Arc::new(LeaderScheduleCache::new_from_bank(&bank));

        let bank_forks = BankForks::new_rw_arc(bank);

        let cluster_info = Arc::new(ClusterInfo::new(
            ContactInfo::new_localhost(&leader_pubkey, timestamp()),
            leader_keypair.clone(),
            SocketAddrSpace::Unspecified,
        ));

        let workers = new_sigverify_workers(cluster_info, leader_schedule_cache.clone(), 4);

        let entries = create_ticks(1, 1, Hash::new_unique());
        let shredder = Shredder::new(1, 0, 1, 0).unwrap();

        let (valid_shreds, _) = shredder.entries_to_merkle_shreds_for_tests(
            &leader_keypair,
            &entries,
            true,
            Hash::new_unique(),
            0,
            0,
            &ReedSolomonCache::default(),
            &mut ProcessShredsStats::default(),
        );

        let (invalid_shreds, _) = shredder.entries_to_merkle_shreds_for_tests(
            &wrong_keypair,
            &entries,
            true,
            Hash::new_unique(),
            0,
            0,
            &ReedSolomonCache::default(),
            &mut ProcessShredsStats::default(),
        );

        let working_bank = bank_forks.read().unwrap().working_bank();

        // Run several independent rounds through the same persistent workers.
        for _ in 0..3 {
            let mut batch = RecycledPacketBatch::with_capacity(5);
            batch.resize(5, Packet::default());

            for index in [0, 2, 4] {
                let shred = &valid_shreds[0];
                batch[index].buffer_mut()[..shred.payload().len()].copy_from_slice(shred.payload());
                batch[index].meta_mut().size = shred.payload().len();
            }

            for index in [1, 3] {
                let shred = &invalid_shreds[0];
                batch[index].buffer_mut()[..shred.payload().len()].copy_from_slice(shred.payload());
                batch[index].meta_mut().size = shred.payload().len();
            }

            let mut batches = vec![PacketBatch::from(batch)];

            verify_packets(
                &workers,
                &Pubkey::new_unique(),
                &working_bank,
                leader_schedule_cache.as_ref(),
                &mut batches,
            );

            assert!(!batches[0].get(0).unwrap().meta().discard());
            assert!(batches[0].get(1).unwrap().meta().discard());
            assert!(!batches[0].get(2).unwrap().meta().discard());
            assert!(batches[0].get(3).unwrap().meta().discard());
            assert!(!batches[0].get(4).unwrap().meta().discard());
        }
    }
}
