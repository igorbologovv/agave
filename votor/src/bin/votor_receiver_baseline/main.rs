use {
    agave_votor_messages::consensus_message::ConsensusMessage,
    std::{env, error::Error, fs},
};

fn main() -> Result<(), Box<dyn Error>> {
    let path = env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: votor_receiver_baseline <message-bytes-file>");
        std::process::exit(1);
    });

    let bytes = fs::read(&path)?;
    println!("read {} bytes from {path}", bytes.len());

    let message: ConsensusMessage = wincode::deserialize(&bytes)?;

    match message {
        ConsensusMessage::Vote(vote_message) => {
            println!("decoded ConsensusMessage::Vote");
            println!("rank: {}", vote_message.rank);
            println!("vote: {:?}", vote_message.vote);
            println!("signature: {:?}", vote_message.signature);
        }
        ConsensusMessage::Certificate(certificate) => {
            println!("decoded ConsensusMessage::Certificate");
            println!("certificate: {:?}", certificate);
        }
    }

    Ok(())
}
