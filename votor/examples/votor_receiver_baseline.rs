#![allow(clippy::arithmetic_side_effects)]

use {
    agave_votor_messages::consensus_message::ConsensusMessage,
    crossbeam_channel::{Receiver, bounded},
    serde::Deserialize,
    solana_keypair::Keypair,
    solana_perf::packet::PacketBatch,
    solana_signer::Signer,
    solana_streamer::{
        nonblocking::{
            quic::SpawnNonBlockingServerResult, swqos::SwQosConfig,
            testing_utilities::spawn_stake_weighted_qos_server,
        },
        quic::QuicStreamerConfig,
        quic_socket::QuicSocket,
        streamer::StakedNodes,
    },
    std::{
        collections::HashMap,
        env, fs,
        net::{IpAddr, SocketAddr, UdpSocket},
        path::PathBuf,
        sync::{
            Arc, RwLock,
            atomic::{AtomicU64, Ordering},
        },
        thread,
        time::Duration,
    },
    tokio::task::JoinHandle,
    tokio_util::sync::CancellationToken,
};

#[derive(Debug, Deserialize)]
struct PeerConfig {
    /// 64-byte Solana ed25519 keypair: secret || public.
    keypair: Vec<u8>,
    stake_lamports: u64,
    ip: IpAddr,
    base_port: u16,
}

#[derive(Debug, Deserialize)]
struct Config {
    peers: Vec<PeerConfig>,
}

struct ServerSlot {
    handle: JoinHandle<()>,
    receiver: Receiver<PacketBatch>,
}

#[derive(Default)]
struct Counters {
    packets: AtomicU64,
    votes: AtomicU64,
    certificates: AtomicU64,
    decode_errors: AtomicU64,
    bytes: AtomicU64,
}

fn usage_and_exit() -> ! {
    eprintln!(
        "usage:\n  cargo run -p agave-votor --example votor_receiver_baseline -- --config <peers.json>\n\noptional:\n  --max-streams-per-second <N>  # accepted for CLI compatibility, currently unused with SwQosConfig::default()"
    );
    std::process::exit(1);
}

fn parse_args() -> (PathBuf, u64) {
    let mut args = env::args().skip(1);

    let mut config_path: Option<PathBuf> = None;
    let mut max_streams_per_second: u64 = 50;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => {
                let Some(value) = args.next() else {
                    usage_and_exit();
                };
                config_path = Some(PathBuf::from(value));
            }
            "--max-streams-per-second" => {
                let Some(value) = args.next() else {
                    usage_and_exit();
                };
                max_streams_per_second = value.parse().unwrap_or_else(|err| {
                    eprintln!("invalid --max-streams-per-second value: {err}");
                    std::process::exit(1);
                });
            }
            _ => usage_and_exit(),
        }
    }

    let Some(config_path) = config_path else {
        usage_and_exit();
    };

    (config_path, max_streams_per_second)
}

fn handle_consensus_message(message: ConsensusMessage, packet_len: usize, counters: &Counters) {
    counters.packets.fetch_add(1, Ordering::Relaxed);
    counters
        .bytes
        .fetch_add(packet_len as u64, Ordering::Relaxed);

    match message {
        ConsensusMessage::Vote(vote_message) => {
            let n = counters.votes.fetch_add(1, Ordering::Relaxed) + 1;

            if n <= 10 || n % 10_000 == 0 {
                println!(
                    "[vote #{n}] rank={} vote={:?}",
                    vote_message.rank, vote_message.vote
                );
            }
        }
        ConsensusMessage::Certificate(certificate) => {
            let n = counters.certificates.fetch_add(1, Ordering::Relaxed) + 1;

            if n <= 10 || n % 10_000 == 0 {
                println!("[cert #{n}] {:?}", certificate);
            }
        }
    }
}

fn process_batch(batch: &PacketBatch, counters: &Counters) {
    for packet in batch.iter() {
        let packet = packet.to_bytes_packet();

        match packet.deserialize_slice::<ConsensusMessage, _>(..) {
            Ok(message) => {
                handle_consensus_message(message, packet.meta().size, counters);
            }
            Err(err) => {
                let n = counters.decode_errors.fetch_add(1, Ordering::Relaxed) + 1;

                if n <= 10 || n % 10_000 == 0 {
                    println!(
                        "[decode-error #{n}] packet_len={} err={err:?}",
                        packet.meta().size
                    );
                }
            }
        }
    }
}

fn spawn_drain_threads(
    receivers: Vec<Receiver<PacketBatch>>,
    counters: Arc<Counters>,
) -> Vec<thread::JoinHandle<()>> {
    const DRAIN_THREADS: usize = 4;

    let shard_size = receivers.len().div_ceil(DRAIN_THREADS).max(1);

    receivers
        .chunks(shard_size)
        .enumerate()
        .map(|(shard_idx, chunk)| {
            let shard: Vec<Receiver<PacketBatch>> = chunk.to_vec();
            let counters = counters.clone();

            thread::Builder::new()
                .name(format!("votor-receiver-drain-{shard_idx}"))
                .spawn(move || {
                    let mut selector = crossbeam_channel::Select::new();

                    for rx in &shard {
                        selector.recv(rx);
                    }

                    loop {
                        let operation = selector.select();
                        let index = operation.index();

                        match operation.recv(&shard[index]) {
                            Ok(batch) => {
                                process_batch(&batch, &counters);
                            }
                            Err(_) => {
                                for rx in &shard {
                                    while let Ok(batch) = rx.try_recv() {
                                        process_batch(&batch, &counters);
                                    }
                                }
                                break;
                            }
                        }
                    }
                })
                .expect("failed to spawn drain thread")
        })
        .collect()
}

fn print_stats(counters: &Counters) {
    let packets = counters.packets.load(Ordering::Relaxed);
    let votes = counters.votes.load(Ordering::Relaxed);
    let certificates = counters.certificates.load(Ordering::Relaxed);
    let decode_errors = counters.decode_errors.load(Ordering::Relaxed);
    let bytes = counters.bytes.load(Ordering::Relaxed);

    println!();
    println!("=== votor receiver baseline stats ===");
    println!("packets:       {packets}");
    println!("votes:         {votes}");
    println!("certificates:  {certificates}");
    println!("decode_errors: {decode_errors}");
    println!("bytes:         {bytes}");
}

fn main() -> anyhow::Result<()> {
    let (config_path, _max_streams_per_second) = parse_args();

    let raw = fs::read_to_string(&config_path)
        .map_err(|err| anyhow::anyhow!("reading {} failed: {err}", config_path.display()))?;

    let config: Config = serde_json::from_str(&raw)
        .map_err(|err| anyhow::anyhow!("parsing {} failed: {err}", config_path.display()))?;

    let num_peers = config.peers.len();
    anyhow::ensure!(num_peers > 0, "config.peers is empty");

    println!(
        "starting votor receiver baseline: config={}, peers={num_peers}",
        config_path.display()
    );

    let mut keypairs: Vec<Keypair> = Vec::with_capacity(num_peers);
    let mut stakes: HashMap<_, u64> = HashMap::with_capacity(num_peers);

    for (idx, peer) in config.peers.iter().enumerate() {
        let keypair = Keypair::try_from(peer.keypair.as_slice()).map_err(|err| {
            anyhow::anyhow!("peers[{idx}].keypair is not a valid 64-byte keypair: {err}")
        })?;

        println!(
            "peer[{idx}] pubkey={} stake={} addr={}:{}",
            keypair.pubkey(),
            peer.stake_lamports,
            peer.ip,
            peer.base_port
        );

        stakes.insert(keypair.pubkey(), peer.stake_lamports);
        keypairs.push(keypair);
    }

    let staked_nodes = Arc::new(RwLock::new(StakedNodes::new(
        Arc::new(stakes),
        HashMap::default(),
    )));

    let cancel = CancellationToken::new();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(32)
        .enable_all()
        .build()?;

    let _runtime_guard = runtime.enter();

    let mut servers: Vec<ServerSlot> = Vec::with_capacity(num_peers);

    for (idx, (keypair, peer)) in keypairs.iter().zip(config.peers.iter()).enumerate() {
        let addr = SocketAddr::new(peer.ip, peer.base_port);

        let socket = UdpSocket::bind(addr)
            .map_err(|err| anyhow::anyhow!("peers[{idx}]: bind {addr}: {err}"))?;

        let (sender, receiver) = bounded(4096);

        let SpawnNonBlockingServerResult { thread: handle, .. } = spawn_stake_weighted_qos_server(
            "votor_receiver_baseline",
            [QuicSocket::Kernel(socket)],
            keypair,
            sender,
            staked_nodes.clone(),
            QuicStreamerConfig {
                max_connections_per_ipaddr_per_min: num_peers as u64 * 1000,
                ..QuicStreamerConfig::default()
            },
            SwQosConfig::default(),
            cancel.clone(),
        )?;

        servers.push(ServerSlot { handle, receiver });

        if (idx + 1) % 100 == 0 || idx + 1 == num_peers {
            println!("spawned {}/{} QUIC receivers", idx + 1, num_peers);
        }
    }

    let counters = Arc::new(Counters::default());

    let receivers: Vec<Receiver<PacketBatch>> = servers
        .iter()
        .map(|server| server.receiver.clone())
        .collect();

    let drain_threads = spawn_drain_threads(receivers, counters.clone());

    println!("all receivers are ready");
    println!("waiting for ConsensusMessage packets; press Ctrl+C to stop");

    loop {
        match runtime.block_on(tokio::time::timeout(
            Duration::from_secs(5),
            tokio::signal::ctrl_c(),
        )) {
            Ok(Ok(())) => break,
            Ok(Err(err)) => return Err(err.into()),
            Err(_) => {
                print_stats(&counters);
            }
        }
    }

    println!("shutdown requested");

    cancel.cancel();

    for server in &servers {
        server.handle.abort();
    }

    drop(servers);

    for handle in drain_threads {
        let _ = handle.join();
    }

    print_stats(&counters);

    Ok(())
}
