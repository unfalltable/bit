use anyhow::{bail, Context, Result};
use bit_app::{
    acknowledge_safety_halt, decode_hash_hex, encode_hex, read_safety_halt,
    safety_halt_journal_path,
};
use std::path::PathBuf;

fn main() -> Result<()> {
    let mut args = std::env::args_os();
    let program = args.next().unwrap_or_default();
    let action = args
        .next()
        .context("missing inspect or acknowledge action")?;
    let state_path = PathBuf::from(args.next().context("missing STATE_DIR argument")?);

    match action.to_string_lossy().as_ref() {
        "inspect" => {
            if args.next().is_some() {
                bail!("inspect accepts only STATE_DIR");
            }
            let Some(record) = read_safety_halt(&state_path)? else {
                println!(
                    "no active safety halt at {}",
                    safety_halt_journal_path(&state_path).display()
                );
                return Ok(());
            };
            println!("record_hash={}", encode_hex(&record.record_hash()));
            println!("reason={:?}", record.reason);
            println!("chain_context={}", encode_hex(&record.chain_context));
            println!("committed_height={}", record.committed_height);
            println!(
                "committed_app_hash={}",
                encode_hex(&record.committed_app_hash)
            );
            println!("attempted_height={}", record.attempted_height);
            println!(
                "attempted_block_hash={}",
                encode_hex(&record.attempted_block_hash)
            );
            println!(
                "attempted_block_time_seconds={}",
                record.attempted_block_time_seconds
            );
            println!(
                "next_validators_hash={}",
                encode_hex(&record.next_validators_hash)
            );
            for (index, hash) in record.evidence_hashes().iter().enumerate() {
                println!("evidence_hash[{index}]={}", encode_hex(hash));
            }
        }
        "acknowledge" => {
            let hash = args.next().context("missing RECORD_HASH argument")?;
            if args.next().is_some() {
                bail!("acknowledge accepts STATE_DIR and RECORD_HASH");
            }
            let hash = decode_hash_hex(&hash.to_string_lossy())?;
            let archive = acknowledge_safety_halt(&state_path, hash)?;
            println!("archived={}", archive.display());
        }
        _ => bail!(
            "usage: {} <inspect STATE_DIR | acknowledge STATE_DIR RECORD_HASH>",
            PathBuf::from(program).display()
        ),
    }
    Ok(())
}
