#[path = "../credential_extractor.rs"]
mod credential_extractor;

// mod http_api;
use credential_extractor::CredentialExtractor;

use std::{env, fs, process, time::Instant};

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} [file]", args[0]);
        process::exit(1);
    }

    let payload = String::from_utf8(fs::read(&args[1])?)?;

    let ts = Instant::now();
    let cred_ex = CredentialExtractor::new(env::var("USE_ML_FOR_CREDS_EXTRACTION").is_ok())?;
    println!(
        "init took {}ms",
        Instant::now().duration_since(ts).as_millis()
    );

    let ts = Instant::now();
    let creds = cred_ex.get_creds(&payload);

    println!(
        "extraction took {}ms",
        Instant::now().duration_since(ts).as_millis()
    );

    println!("creds: {:?}", creds);
    Ok(())
}
