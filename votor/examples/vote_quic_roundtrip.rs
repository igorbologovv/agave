#![allow(clippy::arithmetic_side_effects)]

//! QUIC vote roundtrip benchmark.
//!
//! Model:
//!   coordinator / whale:
//!     - loads one pseudo-real Vote from an existing fixture
//!     - signs it with coordinator BLS key
//!     - sends it to N validator servers
//!
//!   each validator:
//!     - receives coordinator VoteMessage over QUIC
//!     - deserializes it
//!     - signs the same Vote with its own BLS key
//!     - sends its own VoteMessage back to coordinator
//!
//!   coordinator:
//!     - receives N unique validator responses
//!
//! Measured path includes:
//!   - coordinator signing
//!   - coordinator fanout submit
//!   - validator receive + deserialize
//!   - validator BLS signing
//!   - validator response serialization
//!   - validator response send
//!   - coordinator response receive
//!
//! The response path warmup waits until the coordinator observes probes from
//! all unique peer pubkeys before measurement. This keeps handshake/reconnect
//! cost out of the measured roundtrip as much as possible.

use {
    agave_votor::quic_client::VotorQuicClient,
    agave_votor_messages::{
        consensus_message::{ConsensusMessage, VoteMessage},
        vote::Vote,
    },
    anyhow::Context,
    clap::Parser,
    crossbeam_channel::{Receiver, RecvTimeoutError, Select, bounded},
    serde::Deserialize,
    solana_bls_signatures::Signature as BLSSignature,
    solana_keypair::Keypair,
    solana_perf::packet::PacketBatch,
    solana_pubkey::Pubkey,
    solana_runtime::genesis_utils::ValidatorVoteKeypairs,
    solana_signer::Signer,
    solana_streamer::{
        nonblocking::{
            quic::SpawnNonBlockingServerResult, simple_qos::SimpleQosConfig,
            testing_utilities::spawn_simple_qos_server,
        },
        quic::QuicStreamerConfig,
        quic_socket::QuicSocket,
        streamer::StakedNodes,
    },
    solana_tpu_client_next::connection_workers_scheduler::{BindTarget, StakeIdentity},
    std::{
        collections::{HashMap, HashSet},
        fmt,
        fs::File,
        io::BufReader,
        net::{SocketAddr, UdpSocket},
        path::{Path, PathBuf},
        sync::{
            Arc, RwLock,
            atomic::{AtomicBool, AtomicU64, Ordering},
        },
        thread,
        time::{Duration, Instant},
    },
    tokio::task::JoinHandle,
    tokio_util::sync::CancellationToken,
};

const PROBE_PAYLOAD: &[u8] = b"vote-quic-roundtrip-probe";

const RESPONSES_PER_PEER: usize = 2;

const COORDINATOR_WHALE_STAKE: u64 = 1_000_000_000_000;
const SMALL_PEER_STAKE: u64 = 1;

const WARMUP_BATCH_SIZE: usize = 128;
const WARMUP_BATCH_PAUSE: Duration = Duration::from_millis(100);
const WARMUP_DRAIN_SLICE: Duration = Duration::from_millis(750);

const PEER_WORKER_SELECT_TIMEOUT: Duration = Duration::from_millis(100);

#[derive(Debug, Parser)]
#[command(about = "QUIC roundtrip: fixture vote -> validators sign -> responses back")]
struct Cli {
    /// Existing synthetic fixture. Exactly one pseudo-real Vote is extracted from it.
    #[arg(long)]
    input: PathBuf,

    /// Number of small validator peers. The coordinator is an additional validator.
    #[arg(long, default_value_t = 1999)]
    peers: usize,

    /// Max streams per second per connection.
    #[arg(long, default_value_t = 50)]
    max_streams_per_second: u64,

    /// Peer request server channel capacity.
    #[arg(long, default_value_t = 4096)]
    peer_receiver_queue_capacity: usize,

    /// Coordinator response server channel capacity.
    #[arg(long, default_value_t = 1 << 17)]
    response_receiver_queue_capacity: usize,

    /// Server runtime threads.
    #[arg(long, default_value_t = 32)]
    server_runtime_threads: usize,

    /// Client runtime threads.
    #[arg(long, default_value_t = 32)]
    client_runtime_threads: usize,

    /// Number of OS worker threads that drain peer request receivers and sign responses.
    #[arg(long, default_value_t = 32)]
    peer_worker_threads: usize,

    /// Max seconds to wait for validator responses during measurement.
    #[arg(long, default_value_t = 20)]
    response_timeout_secs: u64,

    /// Max seconds to wait until all response clients have warmed up to coordinator.
    #[arg(long, default_value_t = 60)]
    response_warmup_timeout_secs: u64,

    /// Whether to warm up request and response QUIC paths before measurement.
    #[arg(long, default_value_t = true)]
    warmup: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
enum StoredPacketKind {
    Vote,
    Cert,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
struct StoredPacket {
    message_bytes: Vec<u8>,
    remote_pubkey: Pubkey,
    kind: StoredPacketKind,
    slot_index: usize,
    arrival_us: u64,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct StoredWorkload {
    seed: u64,
    num_slots: usize,
    votes_per_slot: usize,
    certs_per_slot: usize,
    base_slot: u64,
    slot_window_us: u64,
    cert_signers: usize,
    num_validators: usize,
    total_packets: usize,
    vote_packets: usize,
    cert_packets: usize,
    packets: Vec<StoredPacket>,
}

struct Server {
    handle: JoinHandle<()>,
    receiver: Receiver<PacketBatch>,
    addr: SocketAddr,
}

struct PeerSlot {
    rank: u16,
    validator: ValidatorVoteKeypairs,
    receiver: Receiver<PacketBatch>,
    response_client: VotorQuicClient,
    coordinator_response_addr: SocketAddr,
}

fn load_first_vote_from_fixture(path: &Path) -> anyhow::Result<Vote> {
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let reader = BufReader::new(file);

    let workload: StoredWorkload =
        bincode::deserialize_from(reader).with_context(|| format!("parse {}", path.display()))?;

    eprintln!(
        "[prepare] fixture: seed={} validators={} total_packets={} vote_packets={} cert_packets={}",
        workload.seed,
        workload.num_validators,
        workload.total_packets,
        workload.vote_packets,
        workload.cert_packets,
    );

    let vote_packet = workload
        .packets
        .into_iter()
        .find(|packet| matches!(packet.kind, StoredPacketKind::Vote))
        .with_context(|| format!("no Vote packet found in {}", path.display()))?;

    let vote_message = match bincode::deserialize::<ConsensusMessage>(&vote_packet.message_bytes)
        .with_context(|| format!("deserialize Vote packet from {}", path.display()))?
    {
        ConsensusMessage::Vote(vote_message) => vote_message,
        ConsensusMessage::Certificate(_) => {
            anyhow::bail!(
                "packet marked as Vote did not contain ConsensusMessage::Vote in {}",
                path.display(),
            );
        }
    };

    eprintln!(
        "[prepare] extracted fixture vote: slot={} remote_pubkey={} slot_index={} arrival_us={}",
        vote_message.vote.slot(),
        vote_packet.remote_pubkey,
        vote_packet.slot_index,
        vote_packet.arrival_us,
    );

    Ok(vote_message.vote)
}

fn build_signed_vote_message_bytes(
    vote: Vote,
    validator: &ValidatorVoteKeypairs,
    rank: u16,
) -> anyhow::Result<Vec<u8>> {
    let payload = wincode::serialize(&vote).context("serialize Vote before BLS signing")?;
    let signature: BLSSignature = validator.bls_keypair.sign(&payload).into();

    let vote_message = VoteMessage {
        vote,
        signature,
        rank,
    };

    let consensus_message = ConsensusMessage::Vote(vote_message);

    bincode::serialize(&consensus_message).context("serialize ConsensusMessage::Vote")
}

fn build_staked_nodes(
    coordinator: &ValidatorVoteKeypairs,
    peers: &[ValidatorVoteKeypairs],
) -> Arc<RwLock<StakedNodes>> {
    let mut stakes: HashMap<Pubkey, u64> = HashMap::with_capacity(peers.len() + 1);

    stakes.insert(coordinator.node_keypair.pubkey(), COORDINATOR_WHALE_STAKE);

    for peer in peers {
        stakes.insert(peer.node_keypair.pubkey(), SMALL_PEER_STAKE);
    }

    Arc::new(RwLock::new(StakedNodes::new(
        Arc::new(stakes),
        HashMap::default(),
    )))
}

fn spawn_server(
    server_runtime: &tokio::runtime::Runtime,
    name: &'static str,
    keypair: &Keypair,
    staked_nodes: Arc<RwLock<StakedNodes>>,
    cancel: CancellationToken,
    receiver_queue_capacity: usize,
    total_validators: usize,
    max_connections_per_peer: usize,
    max_streams_per_second: u64,
) -> anyhow::Result<Server> {
    let _guard = server_runtime.enter();

    let socket = UdpSocket::bind("127.0.0.1:0")
        .with_context(|| format!("{name}: bind ephemeral localhost server socket"))?;
    let addr = socket.local_addr()?;
    let (sender, receiver) = bounded(receiver_queue_capacity);

    let (
        SpawnNonBlockingServerResult {
            endpoints: _,
            stats: _,
            thread: handle,
            max_concurrent_connections: _,
        },
        _banlist,
    ) = spawn_simple_qos_server(
        name,
        [QuicSocket::Kernel(socket)],
        keypair,
        sender,
        staked_nodes,
        QuicStreamerConfig {
            max_connections_per_ipaddr_per_min: total_validators as u64 * 1000,
            ..QuicStreamerConfig::default_for_tests()
        },
        SimpleQosConfig {
            max_streams_per_second,
            max_staked_connections: total_validators + 100,
            max_connections_per_peer,
        },
        cancel,
    )?;

    Ok(Server {
        handle,
        receiver,
        addr,
    })
}

fn spawn_client(
    client_runtime: &tokio::runtime::Runtime,
    keypair: &Keypair,
    cancel: CancellationToken,
    label: &str,
) -> anyhow::Result<VotorQuicClient> {
    let socket = UdpSocket::bind("127.0.0.1:0")
        .with_context(|| format!("{label}: bind ephemeral localhost socket"))?;

    let (client, _update_handler) = VotorQuicClient::new(
        client_runtime.handle().clone(),
        BindTarget::Socket(socket),
        StakeIdentity::new(keypair),
        cancel,
    )?;

    Ok(client)
}

fn warmup_request_path(fanout_client: &mut VotorQuicClient, peer_addrs: &[SocketAddr]) {
    let num_batches = peer_addrs.len().div_ceil(WARMUP_BATCH_SIZE);

    for (batch_index, chunk) in peer_addrs.chunks(WARMUP_BATCH_SIZE).enumerate() {
        fanout_client.send_message_to_peers(PROBE_PAYLOAD.to_vec(), chunk.iter().copied());

        eprintln!(
            "  request warmup batch {}/{}: {} peers",
            batch_index + 1,
            num_batches,
            chunk.len(),
        );

        if batch_index + 1 < num_batches {
            thread::sleep(WARMUP_BATCH_PAUSE);
        }
    }
}

fn send_response_warmup_probes(
    response_clients: &mut [VotorQuicClient],
    coordinator_response_addr: SocketAddr,
) {
    let num_batches = response_clients.len().div_ceil(WARMUP_BATCH_SIZE);

    for (batch_index, chunk) in response_clients.chunks_mut(WARMUP_BATCH_SIZE).enumerate() {
        for client in chunk.iter_mut() {
            client.send_message_to_peers(
                PROBE_PAYLOAD.to_vec(),
                std::iter::once(coordinator_response_addr),
            );
        }

        eprintln!(
            "  response warmup batch {}/{}: {} clients",
            batch_index + 1,
            num_batches,
            chunk.len(),
        );

        if batch_index + 1 < num_batches {
            thread::sleep(WARMUP_BATCH_PAUSE);
        }
    }
}

fn drain_response_warmup_probes(
    receiver: &Receiver<PacketBatch>,
    unique_senders: &mut HashSet<Pubkey>,
    drain_for: Duration,
) {
    let deadline = Instant::now() + drain_for;

    while Instant::now() < deadline {
        match receiver.recv_timeout(Duration::from_millis(25)) {
            Ok(batch) => {
                for packet in batch.iter() {
                    if let Some(remote_pubkey) = packet.meta().remote_pubkey() {
                        unique_senders.insert(remote_pubkey);
                    }
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }

    while let Ok(batch) = receiver.try_recv() {
        for packet in batch.iter() {
            if let Some(remote_pubkey) = packet.meta().remote_pubkey() {
                unique_senders.insert(remote_pubkey);
            }
        }
    }
}

fn warmup_response_path_until_ready(
    response_clients: &mut [VotorQuicClient],
    coordinator_response_receiver: &Receiver<PacketBatch>,
    coordinator_response_addr: SocketAddr,
    expected_unique_peers: usize,
    timeout: Duration,
) -> usize {
    let deadline = Instant::now() + timeout;
    let mut round = 0usize;
    let mut unique_senders = HashSet::<Pubkey>::with_capacity(expected_unique_peers);

    while unique_senders.len() < expected_unique_peers && Instant::now() < deadline {
        round = round.saturating_add(1);

        eprintln!(
            "[warmup] response path round {round}: sending probes; currently warmed {}/{}",
            unique_senders.len(),
            expected_unique_peers,
        );

        send_response_warmup_probes(response_clients, coordinator_response_addr);

        drain_response_warmup_probes(
            coordinator_response_receiver,
            &mut unique_senders,
            WARMUP_DRAIN_SLICE,
        );

        eprintln!(
            "[warmup] response path round {round}: warmed {}/{}",
            unique_senders.len(),
            expected_unique_peers,
        );
    }

    drain_response_warmup_probes(
        coordinator_response_receiver,
        &mut unique_senders,
        Duration::from_millis(250),
    );

    unique_senders.len()
}

fn spawn_response_collector(
    receiver: Receiver<PacketBatch>,
    expected_response_votes: u64,
    responses_per_peer: u64,
    response_count: Arc<AtomicU64>,
    unique_response_peer_count: Arc<AtomicU64>,
    malformed_response_count: Arc<AtomicU64>,
    done: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    thread::Builder::new()
        .name("roundtrip-response-collector".to_string())
        .spawn(move || {
            let mut response_counts_by_sender = HashMap::<Pubkey, u64>::new();

            let process_batch =
                |batch: PacketBatch, response_counts_by_sender: &mut HashMap<Pubkey, u64>| {
                    for packet in batch.iter() {
                        let Ok(ConsensusMessage::Vote(_vote_message)) =
                            packet.deserialize_slice::<ConsensusMessage, _>(..)
                        else {
                            continue;
                        };

                        let Some(remote_pubkey) = packet.meta().remote_pubkey() else {
                            malformed_response_count.fetch_add(1, Ordering::Relaxed);
                            continue;
                        };

                        let peer_response_count =
                            response_counts_by_sender.entry(remote_pubkey).or_insert(0);

                        if *peer_response_count == 0 {
                            unique_response_peer_count.fetch_add(1, Ordering::Relaxed);
                        }

                        if *peer_response_count < responses_per_peer {
                            *peer_response_count += 1;
                            response_count.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                };

            loop {
                match receiver.recv_timeout(Duration::from_millis(100)) {
                    Ok(batch) => {
                        process_batch(batch, &mut response_counts_by_sender);

                        if response_count.load(Ordering::Relaxed) >= expected_response_votes {
                            break;
                        }
                    }
                    Err(RecvTimeoutError::Timeout) => {
                        if done.load(Ordering::Relaxed) {
                            break;
                        }
                    }
                    Err(RecvTimeoutError::Disconnected) => break,
                }
            }

            while let Ok(batch) = receiver.try_recv() {
                process_batch(batch, &mut response_counts_by_sender);
            }
        })
        .expect("spawn response collector")
}

fn process_peer_batch(
    slot: &mut PeerSlot,
    batch: PacketBatch,
    requests_received_count: &Arc<AtomicU64>,
    responses_signed_count: &Arc<AtomicU64>,
    malformed_request_count: &Arc<AtomicU64>,
) {
    for packet in batch.iter() {
        let Ok(ConsensusMessage::Vote(request_vote_message)) =
            packet.deserialize_slice::<ConsensusMessage, _>(..)
        else {
            continue;
        };

        requests_received_count.fetch_add(1, Ordering::Relaxed);

        let received_vote = request_vote_message.vote;

        for _ in 0..RESPONSES_PER_PEER {
            let response_bytes = match build_signed_vote_message_bytes(
                received_vote.clone(),
                &slot.validator,
                slot.rank,
            ) {
                Ok(bytes) => bytes,
                Err(_) => {
                    malformed_request_count.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            };

            slot.response_client.send_message_to_peers(
                response_bytes,
                std::iter::once(slot.coordinator_response_addr),
            );

            responses_signed_count.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn drain_peer_slot(
    slot: &mut PeerSlot,
    requests_received_count: &Arc<AtomicU64>,
    responses_signed_count: &Arc<AtomicU64>,
    malformed_request_count: &Arc<AtomicU64>,
) {
    while let Ok(batch) = slot.receiver.try_recv() {
        process_peer_batch(
            slot,
            batch,
            requests_received_count,
            responses_signed_count,
            malformed_request_count,
        );
    }
}

fn spawn_peer_worker_shards(
    mut slots: Vec<PeerSlot>,
    worker_threads: usize,
    done: Arc<AtomicBool>,
    requests_received_count: Arc<AtomicU64>,
    responses_signed_count: Arc<AtomicU64>,
    malformed_request_count: Arc<AtomicU64>,
) -> Vec<thread::JoinHandle<()>> {
    let shard_count = worker_threads.max(1).min(slots.len().max(1));
    let mut shards: Vec<Vec<PeerSlot>> = (0..shard_count).map(|_| Vec::new()).collect();

    for (index, slot) in slots.drain(..).enumerate() {
        shards[index % shard_count].push(slot);
    }

    shards
        .into_iter()
        .enumerate()
        .filter_map(|(shard_index, mut shard)| {
            if shard.is_empty() {
                return None;
            }

            let done = Arc::clone(&done);
            let requests_received_count = Arc::clone(&requests_received_count);
            let responses_signed_count = Arc::clone(&responses_signed_count);
            let malformed_request_count = Arc::clone(&malformed_request_count);

            Some(
                thread::Builder::new()
                    .name(format!("roundtrip-peer-shard-{shard_index}"))
                    .spawn(move || {
                        let receivers: Vec<Receiver<PacketBatch>> =
                            shard.iter().map(|slot| slot.receiver.clone()).collect();

                        let mut selector = Select::new();
                        for receiver in &receivers {
                            selector.recv(receiver);
                        }

                        loop {
                            match selector.select_timeout(PEER_WORKER_SELECT_TIMEOUT) {
                                Ok(operation) => {
                                    let index = operation.index();

                                    match operation.recv(&receivers[index]) {
                                        Ok(batch) => process_peer_batch(
                                            &mut shard[index],
                                            batch,
                                            &requests_received_count,
                                            &responses_signed_count,
                                            &malformed_request_count,
                                        ),
                                        Err(_) => break,
                                    }
                                }
                                Err(_) => {
                                    if done.load(Ordering::Relaxed) {
                                        break;
                                    }
                                }
                            }
                        }

                        for slot in &mut shard {
                            drain_peer_slot(
                                slot,
                                &requests_received_count,
                                &responses_signed_count,
                                &malformed_request_count,
                            );

                            slot.response_client.shutdown();
                        }
                    })
                    .expect("spawn peer worker shard"),
            )
        })
        .collect()
}

struct RoundtripReport {
    vote_source: &'static str,
    peers_expected: usize,
    responses_per_peer: usize,
    responses_expected: u64,
    peer_worker_threads: usize,
    coordinator_whale_stake: u64,
    small_peer_stake: u64,
    requests_received: u64,
    responses_signed: u64,
    responses_received: u64,
    unique_response_peers: u64,
    malformed_requests: u64,
    malformed_responses: u64,
    fanout_send_elapsed: Duration,
    measured_elapsed: Duration,
}

impl RoundtripReport {
    fn response_delivery_rate(&self) -> f64 {
        if self.responses_expected == 0 {
            0.0
        } else {
            (self.responses_received as f64 / self.responses_expected as f64) * 100.0
        }
    }
}

impl fmt::Display for RoundtripReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter)?;
        writeln!(formatter, "=== Vote QUIC Roundtrip ===")?;
        writeln!(
            formatter,
            "  Vote source:                {}",
            self.vote_source
        )?;
        writeln!(
            formatter,
            "  Peers expected:             {}",
            self.peers_expected
        )?;
        writeln!(
            formatter,
            "  Responses per peer:         {}",
            self.responses_per_peer,
        )?;
        writeln!(
            formatter,
            "  Responses expected:         {}",
            self.responses_expected,
        )?;
        writeln!(
            formatter,
            "  Peer worker threads:        {}",
            self.peer_worker_threads,
        )?;
        writeln!(
            formatter,
            "  Coordinator whale stake:    {}",
            self.coordinator_whale_stake,
        )?;
        writeln!(
            formatter,
            "  Each small peer stake:      {}",
            self.small_peer_stake,
        )?;
        writeln!(
            formatter,
            "  Requests received by peers: {}",
            self.requests_received,
        )?;
        writeln!(
            formatter,
            "  Peer responses signed:      {}",
            self.responses_signed,
        )?;
        writeln!(
            formatter,
            "  Unique responding peers:    {}",
            self.unique_response_peers,
        )?;
        writeln!(
            formatter,
            "  Vote responses received:    {}",
            self.responses_received,
        )?;
        writeln!(
            formatter,
            "  Malformed requests:         {}",
            self.malformed_requests,
        )?;
        writeln!(
            formatter,
            "  Malformed responses:        {}",
            self.malformed_responses,
        )?;
        writeln!(
            formatter,
            "  Response delivery rate:     {:.2}%",
            self.response_delivery_rate(),
        )?;
        writeln!(
            formatter,
            "  Coordinator fanout submit:  {:.3} ms",
            self.fanout_send_elapsed.as_secs_f64() * 1000.0,
        )?;
        writeln!(
            formatter,
            "  Total measured roundtrip:   {:.3} ms",
            self.measured_elapsed.as_secs_f64() * 1000.0,
        )
    }
}

fn main() -> anyhow::Result<()> {
    agave_logger::setup();

    let cli = Cli::parse();

    anyhow::ensure!(cli.peers > 0, "peers must be > 0");
    anyhow::ensure!(
        cli.peers + 1 <= u16::MAX as usize + 1,
        "too many validators for u16 ranks",
    );

    eprintln!(
        "[prepare] loading one pseudo-real Vote from fixture {}",
        cli.input.display(),
    );

    let vote = load_first_vote_from_fixture(&cli.input)?;

    eprintln!("[prepare] vote prepared from fixture: slot={}", vote.slot());

    let total_validators = cli.peers + 1;

    eprintln!(
        "[prepare] generating validators: 1 coordinator whale + {} small peers",
        cli.peers,
    );

    let mut validators: Vec<ValidatorVoteKeypairs> = (0..total_validators)
        .map(|_| ValidatorVoteKeypairs::new_rand())
        .collect();

    let coordinator = validators.remove(0);
    let peers = validators;

    let staked_nodes = build_staked_nodes(&coordinator, &peers);

    eprintln!(
        "[prepare] stakes: coordinator_whale={} each_small_peer={}",
        COORDINATOR_WHALE_STAKE, SMALL_PEER_STAKE,
    );

    let server_cancel = CancellationToken::new();
    let client_cancel = CancellationToken::new();
    let done = Arc::new(AtomicBool::new(false));

    let server_runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(cli.server_runtime_threads)
        .enable_all()
        .thread_name("roundtrip-server")
        .build()?;

    let client_runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(cli.client_runtime_threads)
        .enable_all()
        .thread_name("roundtrip-client")
        .build()?;

    eprintln!("[prepare] spawning coordinator response server");

    let coordinator_response_server = spawn_server(
        &server_runtime,
        "roundtrip_coordinator_response",
        &coordinator.node_keypair,
        staked_nodes.clone(),
        server_cancel.clone(),
        cli.response_receiver_queue_capacity,
        total_validators,
        2,
        cli.max_streams_per_second,
    )?;

    eprintln!(
        "[prepare] coordinator response addr={}",
        coordinator_response_server.addr,
    );

    eprintln!("[prepare] spawning {} peer request servers", cli.peers);

    let mut peer_servers = Vec::with_capacity(cli.peers);

    for (index, peer) in peers.iter().enumerate() {
        let server = spawn_server(
            &server_runtime,
            "roundtrip_peer_request",
            &peer.node_keypair,
            staked_nodes.clone(),
            server_cancel.clone(),
            cli.peer_receiver_queue_capacity,
            total_validators,
            2,
            cli.max_streams_per_second,
        )?;

        peer_servers.push(server);

        if (index + 1) % 100 == 0 {
            eprintln!("  spawned {}/{} peer servers", index + 1, cli.peers);
        }
    }

    let peer_addrs: Vec<SocketAddr> = peer_servers.iter().map(|server| server.addr).collect();

    eprintln!("[prepare] spawning coordinator fanout client");

    let mut coordinator_fanout_client = spawn_client(
        &client_runtime,
        &coordinator.node_keypair,
        client_cancel.clone(),
        "coordinator fanout client",
    )?;

    eprintln!("[prepare] spawning {} peer response clients", cli.peers);

    let mut peer_response_clients = Vec::with_capacity(cli.peers);

    for (index, peer) in peers.iter().enumerate() {
        let client = spawn_client(
            &client_runtime,
            &peer.node_keypair,
            client_cancel.clone(),
            "peer response client",
        )?;

        peer_response_clients.push(client);

        if (index + 1) % 100 == 0 {
            eprintln!(
                "  spawned {}/{} peer response clients",
                index + 1,
                cli.peers
            );
        }
    }

    if cli.warmup {
        eprintln!(
            "[warmup] warming response path: peers -> coordinator; waiting for {} unique peer \
             probes",
            cli.peers,
        );

        let warmed_response_peers = warmup_response_path_until_ready(
            &mut peer_response_clients,
            &coordinator_response_server.receiver,
            coordinator_response_server.addr,
            cli.peers,
            Duration::from_secs(cli.response_warmup_timeout_secs),
        );

        eprintln!(
            "[warmup] response path ready: {}/{} unique peers warmed",
            warmed_response_peers, cli.peers,
        );

        if warmed_response_peers < cli.peers {
            eprintln!(
                "[warmup] WARNING: response path did not fully warm before timeout; measured \
                 roundtrip may include handshake/reconnect cost",
            );
        }
    }

    let response_count = Arc::new(AtomicU64::new(0));
    let unique_response_peer_count = Arc::new(AtomicU64::new(0));
    let requests_received_count = Arc::new(AtomicU64::new(0));
    let responses_signed_count = Arc::new(AtomicU64::new(0));
    let malformed_request_count = Arc::new(AtomicU64::new(0));
    let malformed_response_count = Arc::new(AtomicU64::new(0));

    eprintln!(
        "[prepare] spawning peer worker shards: {} workers for {} peers",
        cli.peer_worker_threads, cli.peers,
    );

    let mut peer_slots = Vec::with_capacity(cli.peers);

    for (peer_index, ((peer, server), response_client)) in peers
        .into_iter()
        .zip(peer_servers.iter())
        .zip(peer_response_clients.into_iter())
        .enumerate()
    {
        let rank = u16::try_from(peer_index + 1).expect("peer rank must fit into u16");

        peer_slots.push(PeerSlot {
            rank,
            validator: peer,
            receiver: server.receiver.clone(),
            response_client,
            coordinator_response_addr: coordinator_response_server.addr,
        });
    }

    let peer_worker_handles = spawn_peer_worker_shards(
        peer_slots,
        cli.peer_worker_threads,
        Arc::clone(&done),
        Arc::clone(&requests_received_count),
        Arc::clone(&responses_signed_count),
        Arc::clone(&malformed_request_count),
    );

    if cli.warmup {
        eprintln!("[warmup] warming request path: coordinator -> peers");
        warmup_request_path(&mut coordinator_fanout_client, &peer_addrs);

        thread::sleep(Duration::from_secs(2));
    }

    let expected_response_votes = (cli.peers * RESPONSES_PER_PEER) as u64;

    let response_collector_handle = spawn_response_collector(
        coordinator_response_server.receiver.clone(),
        expected_response_votes,
        RESPONSES_PER_PEER as u64,
        Arc::clone(&response_count),
        Arc::clone(&unique_response_peer_count),
        Arc::clone(&malformed_response_count),
        Arc::clone(&done),
    );

    eprintln!(
        "[measure] start: coordinator signs fixture vote and sends it to {} peers",
        cli.peers,
    );

    let measured_start = Instant::now();

    let request_bytes = build_signed_vote_message_bytes(vote, &coordinator, 0)?;

    let fanout_send_start = Instant::now();

    coordinator_fanout_client.send_message_to_peers(request_bytes, peer_addrs.iter().copied());

    let fanout_send_elapsed = fanout_send_start.elapsed();

    let deadline = Instant::now() + Duration::from_secs(cli.response_timeout_secs);

    while response_count.load(Ordering::Relaxed) < expected_response_votes
        && Instant::now() < deadline
    {
        thread::sleep(Duration::from_millis(1));
    }

    let measured_elapsed = measured_start.elapsed();

    let requests_received = requests_received_count.load(Ordering::Relaxed);
    let responses_signed = responses_signed_count.load(Ordering::Relaxed);
    let responses_received = response_count.load(Ordering::Relaxed);
    let unique_response_peers = unique_response_peer_count.load(Ordering::Relaxed);
    let malformed_requests = malformed_request_count.load(Ordering::Relaxed);
    let malformed_responses = malformed_response_count.load(Ordering::Relaxed);

    let report = RoundtripReport {
        vote_source: "fixture pseudo-real vote",
        peers_expected: cli.peers,
        responses_per_peer: RESPONSES_PER_PEER,
        responses_expected: expected_response_votes,
        peer_worker_threads: peer_worker_handles.len(),
        coordinator_whale_stake: COORDINATOR_WHALE_STAKE,
        small_peer_stake: SMALL_PEER_STAKE,
        requests_received,
        responses_signed,
        responses_received,
        unique_response_peers,
        malformed_requests,
        malformed_responses,
        fanout_send_elapsed,
        measured_elapsed,
    };

    print!("{report}");

    eprintln!("[shutdown] stopping workers and clients");

    done.store(true, Ordering::Relaxed);

    coordinator_fanout_client.shutdown();
    drop(coordinator_fanout_client);

    for handle in peer_worker_handles {
        let _ = handle.join();
    }

    let _ = response_collector_handle.join();

    client_cancel.cancel();

    eprintln!("[shutdown] stopping servers");

    server_cancel.cancel();

    for server in peer_servers.drain(..) {
        drop(server.receiver);
        server_runtime.block_on(async {
            let _ = server.handle.await;
        });
    }

    drop(coordinator_response_server.receiver);
    server_runtime.block_on(async {
        let _ = coordinator_response_server.handle.await;
    });

    eprintln!("[done] vote QUIC roundtrip finished");

    Ok(())
}
