mod acpi_api;
mod analyzer;
mod analyzers;
mod filelister;
mod inmem_file;
mod yara_rulset;
// mod http_api;
use tracing::{error, span, Level};

use acpi_api::ICAPWorker;
use analyzer::{Analyzer, Location, Sample};
use std::{env, error::Error, net::SocketAddr, path::PathBuf, process};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .pretty()
        .with_thread_names(true)
        .with_max_level(tracing::Level::TRACE)
        .init();

    let c_span = span!(Level::INFO, "main");
    let _g = c_span.enter();

    let args: Vec<String> = env::args().collect();

    if args.len() == 1 {
        error!("Missing arguments!");
        process::exit(1);
    }

    match args[1].as_str() {
        "icap" => {
            let listen_addr = if args.len() > 3 {
                args[2]
                    .parse::<SocketAddr>()
                    .expect("Could not parse SocketAddr")
            } else {
                "0.0.0.0:8000".parse::<SocketAddr>().unwrap()
            };

            run_icap(listen_addr).await?;
        }
        "scan" => {
            let anal = Analyzer::new(PathBuf::from(&args[2]).as_path())?;
            println!(
                "{:?}",
                anal.analyze(Sample::File {
                    name: Some(args[3].clone()),
                    data: Location::File(PathBuf::from(&args[3]))
                })?
            );
        }
        _ => {
            error!("Unknown command '{}'", args[1]);
            process::exit(1);
        }
    }

    Ok(())
}

async fn run_icap(listen_addr: SocketAddr) -> Result<(), Box<dyn Error>> {
    let socket = tokio::net::TcpListener::bind(listen_addr)
        .await
        .expect("Could not open socket");

    loop {
        let (stream, addr) = socket.accept().await?;
        println!("[{:?}]", addr);

        tokio::spawn(async move {
            let mut worker = ICAPWorker::new(stream);
            while let Ok(_) = worker.process_msg().await {}
        });
    }
}
