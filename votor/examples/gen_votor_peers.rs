use {
    solana_keypair::Keypair,
    solana_signer::Signer,
    std::{env, fs, path::PathBuf},
};

fn usage_and_exit() -> ! {
    eprintln!(
        "usage:\n  cargo run -p agave-votor --example gen_votor_peers -- --peers <N> --base-port <PORT> --out <FILE>\n\nexample:\n  cargo run -p agave-votor --example gen_votor_peers -- --peers 1 --base-port 8100 --out /tmp/peers.local.json"
    );
    std::process::exit(1);
}

fn parse_args() -> (usize, u16, PathBuf) {
    let mut args = env::args().skip(1);

    let mut peers: Option<usize> = None;
    let mut base_port: Option<u16> = None;
    let mut out: Option<PathBuf> = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--peers" => {
                let Some(value) = args.next() else {
                    usage_and_exit();
                };
                peers = Some(value.parse().unwrap_or_else(|err| {
                    eprintln!("invalid --peers value: {err}");
                    std::process::exit(1);
                }));
            }
            "--base-port" => {
                let Some(value) = args.next() else {
                    usage_and_exit();
                };
                base_port = Some(value.parse().unwrap_or_else(|err| {
                    eprintln!("invalid --base-port value: {err}");
                    std::process::exit(1);
                }));
            }
            "--out" => {
                let Some(value) = args.next() else {
                    usage_and_exit();
                };
                out = Some(PathBuf::from(value));
            }
            _ => usage_and_exit(),
        }
    }

    let Some(peers) = peers else {
        usage_and_exit();
    };
    let Some(base_port) = base_port else {
        usage_and_exit();
    };
    let Some(out) = out else {
        usage_and_exit();
    };

    if peers == 0 {
        eprintln!("--peers must be greater than 0");
        std::process::exit(1);
    }

    if base_port as usize + peers > u16::MAX as usize {
        eprintln!("base_port + peers exceeds u16 port range");
        std::process::exit(1);
    }

    (peers, base_port, out)
}

fn main() -> std::io::Result<()> {
    let (peers, base_port, out) = parse_args();

    let mut json = String::new();
    json.push_str("{\n");
    json.push_str("  \"peers\": [\n");

    for idx in 0..peers {
        let keypair = Keypair::new();
        let keypair_bytes = keypair.to_bytes();

        let keypair_json = keypair_bytes
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(", ");

        let port = base_port + idx as u16;

        println!(
            "peer[{idx}] pubkey={} addr=127.0.0.1:{port}",
            keypair.pubkey()
        );

        json.push_str("    {\n");
        json.push_str(&format!("      \"keypair\": [{}],\n", keypair_json));
        json.push_str("      \"stake_lamports\": 1,\n");
        json.push_str("      \"ip\": \"127.0.0.1\",\n");
        json.push_str(&format!("      \"base_port\": {port}\n"));
        json.push_str("    }");

        if idx + 1 != peers {
            json.push(',');
        }

        json.push('\n');
    }

    json.push_str("  ]\n");
    json.push_str("}\n");

    fs::write(&out, json)?;

    println!("wrote {}", out.display());

    Ok(())
}
