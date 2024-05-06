mod analyzer;
mod analyzers;
mod config;
mod credential_extractor;
mod filelister;
mod icap_api;
mod inmem_file;
mod yara_rulset;
// mod http_api;
use credential_extractor::CredentialExtractor;
use sentry::ClientInitGuard;
use std::{fs, sync::Arc};
use tracing::{error, info, span, Level};

use analyzer::{Analyzer, Location, Sample};
use icap_api::ICAPWorker;
use std::{env, error::Error, net::SocketAddr, path::PathBuf, process};
use tokio::{
    net::TcpStream,
    sync::mpsc::{channel, Sender},
    task::JoinHandle,
};

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} [scan [file]|serve (config)|ask (file)]", args[0]);
        process::exit(1);
    }

    let conf = if env::var("CONF_FROM_ENV").is_ok_and(|s| s.to_lowercase() == "true") {
        config::Config::read_from_env()?
    } else {
        if args.len() < 3 {
            eprintln!("Missing config file (or missed CONF_FROM_ENV=true)!");
        }
        config::Config::read_from_file(PathBuf::from(&args[1]).as_path())?
    };

    let _g: Option<ClientInitGuard> = if let Some(sentry_endpoint_rule) = conf.sentry_endpoint_url {
        Some(sentry::init((
            sentry_endpoint_rule,
            sentry::ClientOptions {
                release: sentry::release_name!(),
                ..Default::default()
            },
        )))
    } else {
        tracing_subscriber::fmt()
            .with_thread_names(true)
            .with_thread_ids(true)
            .with_max_level(tracing::Level::INFO)
            .init();
        None
    };

    let c_span = span!(Level::INFO, "main");
    let _g = c_span.enter();

    let analyzer = Arc::new(Analyzer::new(conf.yara_rules_file.as_path())?);

    match args[2].as_str() {
        "serve" => {
            info!("Serving ICAP...");
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(run_icap(
                    conf.icap_api_listen_addr
                        .unwrap_or("0.0.0.0:10055".parse::<SocketAddr>().unwrap()),
                    analyzer,
                    conf.icap_num_workers.unwrap_or(8),
                ))
                .expect("Failed to initialize tokio runtime");
        }
        "scan" => {
            if args.len() < 4 {
                // error!("Missing file to scan!");
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
        "ask" => {
            if args.len() < 4 {
                error!("{} [file]", args[0]);
                process::exit(1);
            }

            let payload = String::from_utf8(fs::read(&args[3])?)?;
            println!("payload: \n{}", payload);
            let ex = CredentialExtractor::new()?;

            println!("res: {:?}", ex.get_creds(payload));
        }
        _ => {
            error!("Unknown command '{}'", args[1]);
            process::exit(1);
        }
    }

    info!("Exited");
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
