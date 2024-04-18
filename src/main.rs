mod acpi_api;
mod analyzer;
mod analyzers;
mod config;
mod filelister;
mod inmem_file;
mod yara_rulset;
// mod http_api;
use tracing::{error, info, span, Level};

use acpi_api::ICAPWorker;
use analyzer::{Analyzer, Location, Sample};
use std::{env, error::Error, net::SocketAddr, path::PathBuf, process};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        eprintln!("Usage: {} [conf file] (scan [file]|serve)", args[0]);
        process::exit(1);
    }

    let conf = config::Config::read_from_file(PathBuf::from(&args[1]).as_path())?;

    tracing_subscriber::fmt()
        .pretty()
        .with_thread_names(true)
        .with_max_level(tracing::Level::TRACE)
        .init();

    let c_span = span!(Level::INFO, "main");
    let _g = c_span.enter();

    let analyzer = Analyzer::new(conf.yara_rules_file.as_path())?;

    match args[2].as_str() {
        "serve" => {
            if let Some(icap_api_addr) = conf.icap_api_listen_addr {
                run_icap(icap_api_addr, &analyzer).await?;
            }
        }
        "scan" => {
            if args.len() < 4 {
                error!("Missing file to scan!");
                process::exit(1);
            }

            info!(
                "{:?}",
                analyzer.analyze(
                    Sample {
                        name: Some(args[3].clone()),
                        data: Location::File(PathBuf::from(&args[3])),
                        unpacking_creds: None
                    },
                    None
                )?
            );
        }
        _ => {
            error!("Unknown command '{}'", args[1]);
            process::exit(1);
        }
    }

    Ok(())
}

async fn run_icap(listen_addr: SocketAddr, analyzer: &Analyzer) -> Result<(), Box<dyn Error>> {
    let socket = tokio::net::TcpListener::bind(listen_addr)
        .await
        .expect("Could not open socket");

    loop {
        let (stream, addr) = socket.accept().await?;
        println!("[{:?}]", addr);

        tokio::spawn(async move {
            let mut worker = ICAPWorker::new(stream, analyzer);
            while let Ok(_) = worker.process_msg().await {}
        });
    }
}
