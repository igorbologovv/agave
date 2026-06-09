#![allow(clippy::arithmetic_side_effects)]
//! Standalone QUIC relay server for votor / tpu-client-next benchmarks.
//!
//! Loads N peer definitions from a JSON file and spawns one QUIC server per
//! entry. Each server represents one fake validator identity.
//!
//! Relay behavior:
//!   - peer[i] receives an incoming packet on peer[i].ip:peer[i].base_port
//!   - peer[i] forwards that same packet to every peer[j], j != i
//!   - forwarding uses VotorQuicClient created from peer[i]'s keypair
//!
//! The forwarded packet is marked at byte offset 12 to avoid relay loops.
//! The original benchmark packet layout is:
//!   [slot: u32][send_time_nanos: u64][padding...]
//!
//! So byte 12 is inside padding and does not break latency decoding.

use {
    agave_votor::quic_client::VotorQuicClient,
    clap::Parser,
    crossbeam_channel::{Receiver, bounded},
    serde::Deserialize,
    solana_keypair::Keypair,
    solana_perf::packet::PacketBatch,
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
        collections::HashMap,
        fs,
        net::{IpAddr, SocketAddr, UdpSocket},
        path::PathBuf,
        sync::{
            Arc, RwLock,
            atomic::{AtomicU64, Ordering},
        },
        thread,
    },
    tokio::task::JoinHandle,
    tokio_util::sync::CancellationToken,
};

/// Warmup sentinel — drain threads skip latency recording for this slot.
const PROBE_SLOT: u32 = u32::MAX;

/// First byte after [slot: u32][send_time_nanos: u64].
/// We use it as relay marker to avoid infinite forwarding loops.
const RELAY_MARKER_OFFSET: usize = 12;
const RELAY_MARKER_FORWARDED: u8 = 1;

#[derive(Debug, Deserialize)]
struct PeerConfig {
    /// 64-byte Solana ed25519 keypair (secret || public).
    keypair: Vec<u8>,
    stake_lamports: u64,
    ip: IpAddr,
    base_port: u16,
}

#[derive(Debug, Deserialize)]
struct Config {
    peers: Vec<PeerConfig>,
}

#[derive(Debug, Parser)]
#[command(about = "Standalone QUIC relay server for votor/tpu-client-next benchmarks")]
struct Cli {
    /// Path to the peer config JSON file.
    #[arg(long)]
    config: PathBuf,

    /// Max streams per second per connection (SimpleQos rate limiter).
    #[arg(long, default_value_t = 50)]
    max_streams_per_second: u64,

    /// Slot index below which packets are excluded from latency stats.
    #[arg(long, default_value_t = 5)]
    warmup_slots: u32,
}

struct ServerSlot {
    handle: JoinHandle<()>,
    receiver: Receiver<PacketBatch>,
    addr: SocketAddr,
}

struct RelaySlot {
    receiver: Receiver<PacketBatch>,
    client: VotorQuicClient,
    target_addrs: Vec<SocketAddr>,
}

/// Absolute CLOCK_MONOTONIC nanoseconds — shared across network namespaces
/// on the same host kernel, so client send-timestamps are directly
/// comparable to server receive-timestamps.
fn monotonic_nanos() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };

    // SAFETY: ts is a valid &mut libc::timespec; CLOCK_MONOTONIC is always
    // available on Linux.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    assert_eq!(rc, 0, "clock_gettime(CLOCK_MONOTONIC) failed");

    (ts.tv_sec as u64) * 1_000_000_000 + ts.tv_nsec as u64
}

fn decode_packet(data: &[u8]) -> Option<(u32, u64)> {
    if data.len() < 12 {
        return None;
    }

    let slot = u32::from_le_bytes(data[0..4].try_into().ok()?);
    let send_nanos = u64::from_le_bytes(data[4..12].try_into().ok()?);

    Some((slot, send_nanos))
}

fn is_relayed_packet(data: &[u8]) -> bool {
    data.get(RELAY_MARKER_OFFSET)
        .copied()
        .is_some_and(|marker| marker == RELAY_MARKER_FORWARDED)
}

fn mark_relayed_packet(data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();

    if out.len() > RELAY_MARKER_OFFSET {
        out[RELAY_MARKER_OFFSET] = RELAY_MARKER_FORWARDED;
    }

    out
}

fn main() -> anyhow::Result<()> {
    agave_logger::setup();

    let cli = Cli::parse();

    let raw = fs::read_to_string(&cli.config)
        .map_err(|e| anyhow::anyhow!("reading {}: {e}", cli.config.display()))?;

    let config: Config = serde_json::from_str(&raw)
        .map_err(|e| anyhow::anyhow!("parsing {}: {e}", cli.config.display()))?;

    let num_peers = config.peers.len();
    anyhow::ensure!(num_peers > 0, "config.peers is empty");

    // Parse keypairs and build the staked-nodes map.
    let mut keypairs: Vec<Keypair> = Vec::with_capacity(num_peers);
    let mut stakes: HashMap<_, u64> = HashMap::with_capacity(num_peers);

    for (idx, peer) in config.peers.iter().enumerate() {
        let keypair = Keypair::try_from(peer.keypair.as_slice()).map_err(|e| {
            anyhow::anyhow!("peers[{idx}].keypair is not a valid 64-byte ed25519 keypair: {e}")
        })?;

        stakes.insert(keypair.pubkey(), peer.stake_lamports);
        keypairs.push(keypair);
    }

    let staked_nodes = Arc::new(RwLock::new(StakedNodes::new(
        Arc::new(stakes),
        HashMap::default(),
    )));

    let server_cancel = CancellationToken::new();
    let client_cancel = CancellationToken::new();

    let server_runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(32)
        .enable_all()
        .thread_name("votor-relay-server")
        .build()?;
    let _server_guard = server_runtime.enter();

    // Shared runtime for all outbound relay clients.
    // This mirrors the ingress benchmark shape: many VotorQuicClient instances
    // sharing one larger runtime instead of spawning one runtime per fake node.
    let client_runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(32)
        .enable_all()
        .thread_name("votor-relay-client")
        .build()?;

    println!(
        "Spawning {num_peers} QUIC relay servers from {}...",
        cli.config.display()
    );

    let mut servers: Vec<ServerSlot> = Vec::with_capacity(num_peers);

    for (idx, (keypair, peer)) in keypairs.iter().zip(config.peers.iter()).enumerate() {
        let addr = SocketAddr::new(peer.ip, peer.base_port);

        let socket =
            UdpSocket::bind(addr).map_err(|e| anyhow::anyhow!("peers[{idx}]: bind {addr}: {e}"))?;

        let (sender, receiver) = bounded(4096);

        let (SpawnNonBlockingServerResult { thread: handle, .. }, _banlist) =
            spawn_simple_qos_server(
                "votor_quic_relay_server",
                [QuicSocket::Kernel(socket)],
                keypair,
                sender,
                staked_nodes.clone(),
                QuicStreamerConfig {
                    max_connections_per_ipaddr_per_min: num_peers as u64 * 1000,
                    ..QuicStreamerConfig::default_for_tests()
                },
                SimpleQosConfig {
                    max_streams_per_second: cli.max_streams_per_second,
                    max_staked_connections: num_peers + 100,
                    max_connections_per_peer: 2,
                },
                server_cancel.clone(),
            )?;

        servers.push(ServerSlot {
            handle,
            receiver,
            addr,
        });

        if (idx + 1) % 100 == 0 {
            println!("  spawned {}/{}", idx + 1, num_peers);
        }
    }

    let all_addrs: Vec<SocketAddr> = servers.iter().map(|server| server.addr).collect();

    // Create one outbound VotorQuicClient per fake node identity.
    // peer[i] will forward from StakeIdentity(keypair[i]) to all peers except itself.
    let mut relay_slots: Vec<RelaySlot> = Vec::with_capacity(num_peers);

    for (idx, (server, keypair)) in servers.iter().zip(keypairs.iter()).enumerate() {
        // Important for large local tests:
        // server sockets occupy the configured ports, e.g. 8100..10099.
        // Relay clients must bind to OS-assigned ephemeral ports, otherwise
        // bind_to_localhost_unique() may collide with the fake server ports.
        let client_socket = UdpSocket::bind("127.0.0.1:0").map_err(|e| {
            anyhow::anyhow!("relay client[{idx}]: bind ephemeral localhost socket: {e}")
        })?;

        let (client, _update_handler) = VotorQuicClient::new(
            client_runtime.handle().clone(),
            BindTarget::Socket(client_socket),
            StakeIdentity::new(keypair),
            client_cancel.clone(),
        )?;

        let target_addrs: Vec<SocketAddr> = all_addrs
            .iter()
            .copied()
            .enumerate()
            .filter_map(|(target_idx, addr)| (target_idx != idx).then_some(addr))
            .collect();

        relay_slots.push(RelaySlot {
            receiver: server.receiver.clone(),
            client,
            target_addrs,
        });
    }

    println!("All {num_peers} relay servers ready — waiting for Ctrl+C");
    println!("Each fake node will forward original packets to all peers except itself");

    let received_count = Arc::new(AtomicU64::new(0));
    let direct_received_count = Arc::new(AtomicU64::new(0));
    let relayed_received_count = Arc::new(AtomicU64::new(0));
    let relay_send_count = Arc::new(AtomicU64::new(0));

    let latencies: Arc<std::sync::Mutex<Vec<f64>>> = Arc::new(std::sync::Mutex::new(Vec::new()));

    // Shard N relay slots across K=4 OS threads with crossbeam Select.
    // Important: Select borrows a separate Vec<Receiver<_>>, not the RelaySlot
    // objects themselves, so each thread can still mutably use the matching
    // VotorQuicClient for forwarding.
    const DRAIN_THREADS: usize = 4;

    let mut shards: Vec<Vec<RelaySlot>> = (0..DRAIN_THREADS).map(|_| Vec::new()).collect();

    for (idx, slot) in relay_slots.into_iter().enumerate() {
        shards[idx % DRAIN_THREADS].push(slot);
    }

    let warmup_threshold = cli.warmup_slots;

    let receiver_handles: Vec<thread::JoinHandle<()>> = shards
        .into_iter()
        .enumerate()
        .filter_map(|(shard_idx, mut shard)| {
            if shard.is_empty() {
                return None;
            }

            let latencies = latencies.clone();
            let received_count = received_count.clone();
            let direct_received_count = direct_received_count.clone();
            let relayed_received_count = relayed_received_count.clone();
            let relay_send_count = relay_send_count.clone();

            Some(
                thread::Builder::new()
                    .name(format!("relay-drain-{shard_idx}"))
                    .spawn(move || {
                        let receivers: Vec<Receiver<PacketBatch>> =
                            shard.iter().map(|slot| slot.receiver.clone()).collect();

                        let mut selector = crossbeam_channel::Select::new();
                        for receiver in &receivers {
                            selector.recv(receiver);
                        }

                        let mut local_latencies: Vec<f64> = Vec::new();

                        let process = |slot: &mut RelaySlot,
                                       batch: &PacketBatch,
                                       local: &mut Vec<f64>| {
                            let recv_nanos = monotonic_nanos();

                            for packet in batch.iter() {
                                let packet = packet.to_bytes_packet();
                                let data = packet.buffer();

                                let decoded = decode_packet(data);
                                let is_relayed = is_relayed_packet(data);

                                if let Some((slot_number, send_nanos)) = decoded {
                                    if slot_number != PROBE_SLOT {
                                        received_count.fetch_add(1, Ordering::Relaxed);

                                        if is_relayed {
                                            relayed_received_count.fetch_add(1, Ordering::Relaxed);
                                        } else {
                                            direct_received_count.fetch_add(1, Ordering::Relaxed);
                                        }

                                        if slot_number >= warmup_threshold {
                                            let us = recv_nanos.saturating_sub(send_nanos) as f64
                                                / 1000.0;
                                            local.push(us);
                                        }
                                    }
                                }

                                // Forward only original benchmark packets.
                                // Forwarded packets have marker at byte 12, so they stop here and
                                // do not create a relay storm.
                                //
                                // PROBE_SLOT is forwarded too. This lets the relay clients warm up
                                // their outbound connections before measured traffic.
                                if decoded.is_some() && !is_relayed && !slot.target_addrs.is_empty()
                                {
                                    let forwarded = mark_relayed_packet(data);
                                    let targets = slot.target_addrs.iter().copied();

                                    slot.client.send_message_to_peers(forwarded, targets);

                                    relay_send_count.fetch_add(
                                        slot.target_addrs.len() as u64,
                                        Ordering::Relaxed,
                                    );
                                }
                            }
                        };

                        loop {
                            let operation = selector.select();
                            let index = operation.index();

                            match operation.recv(&receivers[index]) {
                                Ok(batch) => {
                                    process(&mut shard[index], &batch, &mut local_latencies);
                                }
                                Err(_) => {
                                    for slot in &mut shard {
                                        while let Ok(batch) = slot.receiver.try_recv() {
                                            process(slot, &batch, &mut local_latencies);
                                        }

                                        slot.client.shutdown();
                                    }

                                    break;
                                }
                            }
                        }

                        latencies
                            .lock()
                            .expect("lock poisoned")
                            .extend_from_slice(&local_latencies);
                    })
                    .expect("spawn relay drain thread"),
            )
        })
        .collect();

    // Block until Ctrl+C.
    server_runtime.block_on(tokio::signal::ctrl_c()).ok();
    println!("Ctrl+C — shutting down...");

    server_cancel.cancel();

    for server in servers.drain(..) {
        drop(server.receiver);
        server_runtime.block_on(async {
            let _ = server.handle.await;
        });
    }

    for handle in receiver_handles {
        let _ = handle.join();
    }

    client_cancel.cancel();

    let total_received = received_count.load(Ordering::Relaxed);
    let direct_received = direct_received_count.load(Ordering::Relaxed);
    let relayed_received = relayed_received_count.load(Ordering::Relaxed);
    let total_relay_sends = relay_send_count.load(Ordering::Relaxed);

    println!("\n=== Relay Counters ===");
    println!("  Total packets received:   {total_received}");
    println!("  Direct packets received:  {direct_received}");
    println!("  Relayed packets received: {relayed_received}");
    println!("  Relay sends attempted:    {total_relay_sends}");

    let latencies = latencies.lock().expect("lock poisoned");

    if latencies.is_empty() {
        println!("No measured latency samples (all traffic was warmup/probe).");
        return Ok(());
    }

    let n = latencies.len();
    let mean = latencies.iter().sum::<f64>() / n as f64;
    let variance = latencies
        .iter()
        .map(|value| (value - mean) * (value - mean))
        .sum::<f64>()
        / n as f64;
    let stddev = variance.sqrt();

    let mut sorted = latencies.clone();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());

    println!("\n=== Relay Latency Statistics (microseconds, CLOCK_MONOTONIC) ===");
    println!("  Samples: {n}");
    println!("  Mean:    {mean:.1} us");
    println!("  Stddev:  {stddev:.1} us");
    println!("  Min:     {:.1} us", sorted[0]);
    println!("  P50:     {:.1} us", sorted[n / 2]);
    println!("  P99:     {:.1} us", sorted[(n as f64 * 0.99) as usize]);
    println!("  Max:     {:.1} us", sorted[n - 1]);

    Ok(())
}
