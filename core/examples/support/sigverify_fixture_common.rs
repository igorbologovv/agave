#![allow(dead_code)]

extern crate clap4 as clap;

use {
    agave_votor::{
        consensus_metrics::ConsensusMetricsEvent,
        consensus_pool::certificate_builder::CertificateBuilder,
        generated_cert_types::GeneratedCertTypes,
    },
    agave_votor_messages::{
        consensus_message::{Certificate, CertificateType, ConsensusMessage, VoteMessage},
        migration::MigrationStatus,
        reward_certificate::AddVoteMessage,
        vote::Vote,
    },
    clap::Parser,
    crossbeam_channel::{Receiver, bounded},
    rand::{Rng, RngCore, SeedableRng, rngs::StdRng},
    rayon::prelude::*,
    solana_bls_signatures::Signature as BLSSignature,
    solana_core::{
        bls_sigverify::bls_sigverifier::{SigVerifier, SigVerifierChannels, SigVerifierContext},
        cluster_info_vote_listener::VerifiedVoterSlotsReceiver,
    },
    solana_gossip::{cluster_info::ClusterInfo, contact_info::ContactInfo},
    solana_hash::Hash,
    solana_keypair::{Keypair, Signer},
    solana_ledger::leader_schedule_cache::LeaderScheduleCache,
    solana_net_utils::SocketAddrSpace,
    solana_perf::packet::{Packet, PacketBatch, RecycledPacketBatch},
    solana_pubkey::Pubkey,
    solana_runtime::{
        bank::Bank,
        bank_forks::BankForks,
        genesis_utils::{
            ValidatorVoteKeypairs, create_genesis_config_with_alpenglow_vote_accounts,
        },
    },
    solana_streamer::nonblocking::simple_qos::SimpleQosBanlist,
    std::{
        convert::TryFrom,
        fs::File,
        io::{BufReader, BufWriter},
        path::Path,
        sync::Arc,
    },
};

pub const CHANNEL_SIZE: usize = 1024;
pub const CERT_SIGNERS: usize = 1500;

// Synthetic slot duration used only for assigning packet arrival times.
pub const SLOT_WINDOW_US: u64 = 200_000;

#[derive(Debug, Clone, Parser)]
pub struct FixtureBuildConfig {
    #[arg(long, help = "Seed value kept for reproducibility and metadata")]
    pub seed: u64,

    #[arg(long = "num-slots", help = "Number of slots to generate")]
    pub num_slots: usize,

    #[arg(
        long = "votes-per-slot",
        help = "Number of vote packets generated per slot"
    )]
    pub votes_per_slot: usize,

    #[arg(
        long = "certs-per-slot",
        help = "Number of certificate packets generated per slot"
    )]
    pub certs_per_slot: usize,

    #[arg(
        long = "base-slot",
        default_value_t = 10,
        help = "First slot used in the synthetic dataset"
    )]
    pub base_slot: u64,

    #[arg(long = "num-validators", help = "Size of the synthetic validator set")]
    pub num_validators: usize,

    #[arg(long = "output", help = "Path to write the fixture file")]
    pub output: String,
}

#[derive(Debug, Clone, Parser)]
pub struct ReplayConfig {
    #[arg(long, help = "Emit CSV output instead of human-readable output")]
    pub csv: bool,

    #[arg(
        long = "input",
        help = "Path to a previously generated workload fixture"
    )]
    pub input: String,

    #[arg(
        long = "poll-interval-us",
        default_value_t = 100,
        help = "Synthetic streamer poll interval in microseconds"
    )]
    pub poll_interval_us: u64,

    #[arg(
        long = "max-packets-per-batch",
        default_value_t = 1024,
        help = "Maximum number of packets emitted in one synthetic streamer batch"
    )]
    pub max_packets_per_batch: usize,

    #[arg(
        long = "num-threads",
        help = "Thread count for the verifier thread pool"
    )]
    pub num_threads: usize,
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub enum StoredPacketKind {
    Vote,
    Cert,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredPacket {
    pub message_bytes: Vec<u8>,
    pub remote_pubkey: Pubkey,
    pub kind: StoredPacketKind,
    pub slot_index: usize,
    pub arrival_us: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredWorkload {
    pub seed: u64,
    pub num_slots: usize,
    pub votes_per_slot: usize,
    pub certs_per_slot: usize,
    pub base_slot: u64,
    pub slot_window_us: u64,
    pub cert_signers: usize,
    pub num_validators: usize,
    pub total_packets: usize,
    pub vote_packets: usize,
    pub cert_packets: usize,
    pub packets: Vec<StoredPacket>,
}

#[derive(Debug, serde::Serialize)]
pub struct OutputRow {
    pub seed: u64,
    pub poll_interval_us: u64,
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
    pub elapsed_us: u64,
    pub per_packet_us: u64,
}

pub struct ExampleContext {
    pub verifier: SigVerifier,
    pub validator_keypairs: Vec<ValidatorVoteKeypairs>,
    pub validator_ranks: Vec<u16>,
    pub _repair_receiver: VerifiedVoterSlotsReceiver,
    pub _reward_receiver: Receiver<AddVoteMessage>,
    pub _pool_receiver: Receiver<Vec<ConsensusMessage>>,
    pub _metrics_receiver: Receiver<(std::time::Instant, Vec<ConsensusMetricsEvent>)>,
}

pub fn validate_fixture_build_config(config: &FixtureBuildConfig) -> Result<(), String> {
    if config.num_slots == 0 {
        return Err("num_slots must be > 0".to_string());
    }
    if config.votes_per_slot == 0 && config.certs_per_slot == 0 {
        return Err("votes_per_slot and certs_per_slot cannot both be 0".to_string());
    }
    if config.num_validators == 0 {
        return Err("num_validators must be > 0".to_string());
    }
    if config.num_validators < CERT_SIGNERS {
        return Err(format!(
            "num_validators must be >= {CERT_SIGNERS} so synthetic certificates have enough \
             signers"
        ));
    }
    Ok(())
}

pub fn validate_replay_config(config: &ReplayConfig) -> Result<(), String> {
    if config.poll_interval_us == 0 {
        return Err("poll_interval_us must be > 0".to_string());
    }
    if config.max_packets_per_batch == 0 {
        return Err("max_packets_per_batch must be > 0".to_string());
    }
    if config.num_threads == 0 {
        return Err("num_threads must be > 0".to_string());
    }
    Ok(())
}

fn derive_key_seed(global_seed: u64, validator_index: usize, key_kind: u64) -> [u8; 32] {
    let mixed = global_seed
        ^ (validator_index as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)
        ^ key_kind.wrapping_mul(0xD6E8_FD50_4E33_9A4D);

    let mut rng = StdRng::seed_from_u64(mixed);
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    seed
}

fn make_deterministic_validator_vote_keypairs(
    global_seed: u64,
    num_validators: usize,
) -> Vec<ValidatorVoteKeypairs> {
    (0..num_validators)
        .map(|validator_index| {
            let node_seed = derive_key_seed(global_seed, validator_index, 0);
            let vote_seed = derive_key_seed(global_seed, validator_index, 1);
            let stake_seed = derive_key_seed(global_seed, validator_index, 2);

            let node_keypair = Keypair::new_from_array(node_seed);
            let vote_keypair = Keypair::new_from_array(vote_seed);
            let stake_keypair = Keypair::new_from_array(stake_seed);

            ValidatorVoteKeypairs::new(node_keypair, vote_keypair, stake_keypair)
        })
        .collect()
}

#[allow(clippy::arithmetic_side_effects)]
pub fn init_example_context(
    num_threads: usize,
    num_validators: usize,
    seed: u64,
) -> ExampleContext {
    let validator_keypairs = make_deterministic_validator_vote_keypairs(seed, num_validators);

    let stakes: Vec<_> = (0..validator_keypairs.len()).map(|_| 1_000_u64).collect();

    let genesis = create_genesis_config_with_alpenglow_vote_accounts(
        1_000_000_000,
        &validator_keypairs,
        stakes,
    );

    let bank0 = Bank::new_for_tests(&genesis.genesis_config);
    let (bank0, _temp_bank_forks) = bank0.wrap_with_bank_forks_for_tests();

    let mut parent = bank0;
    let mut bank = Bank::new_from_parent(
        parent.clone(),
        solana_runtime::bank::SlotLeader::default(),
        1,
    );

    for i in 2..10 {
        parent = Arc::new(bank);
        bank = Bank::new_from_parent(
            parent.clone(),
            solana_runtime::bank::SlotLeader::default(),
            i,
        );
    }

    let bank_forks = BankForks::new_rw_arc(bank);
    let sharable_banks = bank_forks
        .read()
        .expect("bank_forks poisoned")
        .sharable_banks();

    let root_bank = sharable_banks.root();
    let rank_map = root_bank
        .get_rank_map(10)
        .expect("rank map for slot 10 must exist in bench");

    let validator_ranks: Vec<u16> = validator_keypairs
        .iter()
        .map(|validator| {
            let validator_bls_pubkey = validator.bls_keypair.public;

            (0..validator_keypairs.len())
                .find_map(|i| {
                    rank_map.get_pubkey_stake_entry(i).and_then(|entry| {
                        (entry.bls_pubkey == validator_bls_pubkey)
                            .then_some(u16::try_from(i).expect("validator index must fit into u16"))
                    })
                })
                .expect("validator BLS pubkey must exist in rank map")
        })
        .collect();

    let keypair = Keypair::new();
    let contact_info = ContactInfo::new_localhost(&keypair.pubkey(), 0);

    let cluster_info = Arc::new(ClusterInfo::new(
        contact_info,
        Arc::new(keypair),
        SocketAddrSpace::Unspecified,
    ));

    let leader_schedule = Arc::new(LeaderScheduleCache::new_from_bank(&sharable_banks.root()));

    let (repair_sender, repair_receiver) = bounded(CHANNEL_SIZE);
    let (reward_sender, reward_receiver) = bounded(CHANNEL_SIZE);
    let (pool_sender, pool_receiver) = bounded(CHANNEL_SIZE);
    let (metrics_sender, metrics_receiver) = bounded(CHANNEL_SIZE);
    let (_packet_sender, packet_receiver) = bounded(CHANNEL_SIZE);

    let banlist = {
        let (banlist, _) = SimpleQosBanlist::new();
        Arc::new(banlist)
    };

    let generated_cert_types = Arc::new(GeneratedCertTypes::default());

    let verifier = SigVerifier::new(
        SigVerifierContext::new(
            Arc::new(MigrationStatus::default()),
            banlist,
            sharable_banks,
            cluster_info,
            leader_schedule,
            num_threads,
            generated_cert_types,
        ),
        SigVerifierChannels::new(
            packet_receiver,
            repair_sender,
            reward_sender,
            pool_sender,
            metrics_sender,
        ),
    );

    ExampleContext {
        verifier,
        validator_keypairs,
        validator_ranks,
        _repair_receiver: repair_receiver,
        _reward_receiver: reward_receiver,
        _pool_receiver: pool_receiver,
        _metrics_receiver: metrics_receiver,
    }
}

pub fn create_signed_vote_message(
    validator_keypairs: &[ValidatorVoteKeypairs],
    validator_ranks: &[u16],
    vote: Vote,
    validator_index: usize,
) -> VoteMessage {
    let bls_keypair = &validator_keypairs[validator_index].bls_keypair;
    let payload = wincode::serialize(&vote).expect("failed to serialize vote");
    let signature: BLSSignature = bls_keypair.sign(&payload).into();
    VoteMessage {
        vote,
        signature,
        rank: validator_ranks[validator_index],
    }
}

pub fn create_signed_certificate_message(
    validator_keypairs: &[ValidatorVoteKeypairs],
    validator_ranks: &[u16],
    cert_type: CertificateType,
    validator_indices: &[usize],
) -> Certificate {
    let mut builder = CertificateBuilder::new(cert_type);
    let vote = cert_type.to_source_vote();

    let vote_messages: Vec<VoteMessage> = validator_indices
        .iter()
        .map(|&validator_index| {
            create_signed_vote_message(validator_keypairs, validator_ranks, vote, validator_index)
        })
        .collect();

    builder
        .aggregate(&vote_messages)
        .expect("failed to aggregate votes for synthetic certificate");

    builder
        .build()
        .expect("failed to build synthetic certificate")
}

pub fn build_vote_message_and_remote(
    ctx: &ExampleContext,
    slot: u64,
    block_id: Hash,
    global_vote_index: usize,
) -> (ConsensusMessage, Pubkey) {
    let validator_index = global_vote_index % ctx.validator_keypairs.len();
    let validator = &ctx.validator_keypairs[validator_index];
    let rank = ctx.validator_ranks[validator_index];

    let vote = Vote::new_notarization_vote(slot, block_id);
    let payload = wincode::serialize(&vote).expect("failed to serialize vote");
    let signature = validator.bls_keypair.sign(&payload).into();

    let vote_msg = VoteMessage {
        vote,
        signature,
        rank,
    };

    (
        ConsensusMessage::Vote(vote_msg),
        validator.node_keypair.pubkey(),
    )
}

pub fn build_cert_message_and_remote(
    ctx: &ExampleContext,
    slot: u64,
    block_id: Hash,
) -> (ConsensusMessage, Pubkey) {
    let cert_type = CertificateType::Notarize(slot, block_id);

    let validator_indices: Vec<usize> = (0..CERT_SIGNERS).collect();
    let cert = create_signed_certificate_message(
        &ctx.validator_keypairs,
        &ctx.validator_ranks,
        cert_type,
        &validator_indices,
    );

    (
        ConsensusMessage::Certificate(cert),
        ctx.validator_keypairs[0].node_keypair.pubkey(),
    )
}

pub fn consensus_message_to_stored_packet(
    message: &ConsensusMessage,
    remote_pubkey: Pubkey,
    kind: StoredPacketKind,
    slot_index: usize,
    arrival_us: u64,
) -> StoredPacket {
    let message_bytes = bincode::serialize(message).expect("failed to serialize message");
    StoredPacket {
        message_bytes,
        remote_pubkey,
        kind,
        slot_index,
        arrival_us,
    }
}

pub fn stored_packet_to_packet(stored: StoredPacket) -> Packet {
    let mut packet = Packet::default();
    let data_len = stored.message_bytes.len();

    packet.buffer_mut()[..data_len].copy_from_slice(&stored.message_bytes);
    packet.meta_mut().size = data_len;
    packet.meta_mut().set_remote_pubkey(stored.remote_pubkey);

    packet
}

#[allow(clippy::arithmetic_side_effects)]
pub fn build_stored_workload(ctx: &ExampleContext, config: &FixtureBuildConfig) -> StoredWorkload {
    let total_packets = config
        .num_slots
        .saturating_mul(config.votes_per_slot.saturating_add(config.certs_per_slot));

    let per_slot_packets: Vec<Vec<StoredPacket>> = (0..config.num_slots)
        .into_par_iter()
        .map(|slot_index| {
            let slot = config.base_slot + slot_index as u64;
            let block_id = Hash::new_unique();

            let mut slot_rng = StdRng::seed_from_u64(
                config.seed ^ (slot_index as u64).wrapping_mul(0xA076_1D64_78BD_642F),
            );

            let slot_base_arrival_us = slot_index as u64 * SLOT_WINDOW_US;

            let mut slot_packets =
                Vec::with_capacity(config.votes_per_slot + config.certs_per_slot);

            let vote_base_index = slot_index.saturating_mul(config.votes_per_slot);

            for vote_index_in_slot in 0..config.votes_per_slot {
                let global_vote_index = vote_base_index.saturating_add(vote_index_in_slot);

                let (message, remote_pubkey) =
                    build_vote_message_and_remote(ctx, slot, block_id, global_vote_index);

                let arrival_us =
                    slot_base_arrival_us + slot_rng.gen_range(0..SLOT_WINDOW_US);

                slot_packets.push(consensus_message_to_stored_packet(
                    &message,
                    remote_pubkey,
                    StoredPacketKind::Vote,
                    slot_index,
                    arrival_us,
                ));
            }

            for _ in 0..config.certs_per_slot {
                let (message, remote_pubkey) = build_cert_message_and_remote(ctx, slot, block_id);

                let arrival_us =
                    slot_base_arrival_us + slot_rng.gen_range(0..SLOT_WINDOW_US);

                slot_packets.push(consensus_message_to_stored_packet(
                    &message,
                    remote_pubkey,
                    StoredPacketKind::Cert,
                    slot_index,
                    arrival_us,
                ));
            }

            slot_packets
        })
        .collect();

    let mut packets = per_slot_packets.into_iter().flatten().collect::<Vec<_>>();
    packets.sort_by_key(|packet| packet.arrival_us);

    StoredWorkload {
        seed: config.seed,
        num_slots: config.num_slots,
        votes_per_slot: config.votes_per_slot,
        certs_per_slot: config.certs_per_slot,
        base_slot: config.base_slot,
        slot_window_us: SLOT_WINDOW_US,
        cert_signers: CERT_SIGNERS,
        num_validators: config.num_validators,
        total_packets,
        vote_packets: config.num_slots.saturating_mul(config.votes_per_slot),
        cert_packets: config.num_slots.saturating_mul(config.certs_per_slot),
        packets,
    }
}

pub fn stored_workload_to_streamer_batches(
    workload: &StoredWorkload,
    poll_interval_us: u64,
    max_packets_per_batch: usize,
) -> Vec<PacketBatch> {
    assert!(poll_interval_us > 0);
    assert!(max_packets_per_batch > 0);

    if workload.packets.is_empty() {
        return Vec::new();
    }

    let mut batches = Vec::new();
    let mut index = 0;

    while index < workload.packets.len() {
        let first_arrival_us = workload.packets[index].arrival_us;
        let poll_start_us = first_arrival_us - (first_arrival_us % poll_interval_us);
        let poll_end_us = poll_start_us.saturating_add(poll_interval_us);

        while index < workload.packets.len() && workload.packets[index].arrival_us < poll_end_us {
            let mut packets = Vec::with_capacity(max_packets_per_batch);

            while index < workload.packets.len()
                && workload.packets[index].arrival_us < poll_end_us
                && packets.len() < max_packets_per_batch
            {
                packets.push(stored_packet_to_packet(workload.packets[index].clone()));
                index += 1;
            }

            if !packets.is_empty() {
                batches.push(RecycledPacketBatch::new(packets).into());
            }
        }
    }

    batches
}

pub fn save_workload_to_file<P: AsRef<Path>>(
    workload: &StoredWorkload,
    path: P,
) -> Result<(), Box<dyn std::error::Error>> {
    let writer = BufWriter::new(File::create(path)?);
    bincode::serialize_into(writer, workload)?;
    Ok(())
}

pub fn load_workload_from_file<P: AsRef<Path>>(
    path: P,
) -> Result<StoredWorkload, Box<dyn std::error::Error>> {
    let reader = BufReader::new(File::open(path)?);
    let workload = bincode::deserialize_from(reader)?;
    Ok(workload)
}

pub fn print_results(row: &OutputRow, csv_output: bool) {
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