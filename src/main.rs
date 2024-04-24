mod analyzer;
mod analyzers;
mod config;
mod filelister;
mod icap_api;
mod inmem_file;
mod yara_rulset;
// mod http_api;
use std::sync::Arc;
use tracing::{error, info, span, Level};

use analyzer::{Analyzer, Location, Sample};
use icap_api::ICAPWorker;
use std::{env, error::Error, net::SocketAddr, path::PathBuf, process};
use tokio::{
    net::TcpStream,
    sync::mpsc::{channel, Sender},
    task::JoinHandle,
};

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

    let analyzer = Arc::new(Analyzer::new(conf.yara_rules_file.as_path())?);

    match args[2].as_str() {
        "serve" => {
            run_icap(
                conf.icap_api_listen_addr
                    .unwrap_or("0.0.0.0:10055".parse::<SocketAddr>().unwrap()),
                analyzer,
                conf.icap_num_workers.unwrap_or(8),
            )
            .await?;
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
                    if args.len() > 4 {
                        Some(args[4].as_str())
                    } else {
                        None
                    }
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

async fn run_icap(
    listen_addr: SocketAddr,
    analyzer: Arc<Analyzer>,
    num_workers: usize,
) -> Result<(), Box<dyn Error>> {
    let c_span = span!(Level::DEBUG, "ICAP");
    let _guard = c_span.enter();

    let socket = tokio::net::TcpListener::bind(listen_addr)
        .await
        .expect("Could not open socket");

    let mut workers: Vec<(JoinHandle<()>, Sender<TcpStream>)> = Vec::new();

    for _ in 0..num_workers {
        let (tx, rx) = channel(100);

        let c_ana = analyzer.clone();
        let handle = tokio::spawn(async move {
            let mut worker = ICAPWorker::new(rx, c_ana.as_ref());
            worker.run().await;
        });

        workers.push((handle, tx));
    }

    let mut c_worker = 0usize;

    loop {
        let (stream, addr) = socket.accept().await?;

        println!("[{:?}]", addr);
        if let Err(e) = workers.as_mut_slice()[c_worker].1.send(stream).await {
            error!("Could not enqueue stream into worker {}: {:?}", c_worker, e);
        }
        c_worker = (c_worker + 1) % num_workers;
    }
}
