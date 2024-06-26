mod analyzer;
mod analyzers;
mod config;
mod credential_extractor;
mod filelister;
mod icap_api;
mod inmem_file;
mod yara_ruleset;

use sentry::ClientInitGuard;
use std::sync::Arc;
use tracing::{error, info};

use analyzer::Analyzer;
use icap_api::ICAPWorker;
use std::{env, error::Error, net::SocketAddr, path::PathBuf};

use tokio::{
    net::TcpStream,
    sync::mpsc::{channel, Sender},
    task::JoinHandle,
};

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();

    let conf = if env::var("CONF_FROM_ENV").is_ok_and(|s| s.to_lowercase() == "true") {
        config::Config::read_from_env()?
    } else {
        if args.len() < 2 {
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
        tracing_subscriber::fmt().with_line_number(true).init();
        None
    };

    let analyzer = Arc::new(Analyzer::new(conf.yara_rules.as_path())?);

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

    info!("Exited");
    Ok(())
}

async fn run_icap(
    listen_addr: SocketAddr,
    analyzer: Arc<Analyzer>,
    num_workers: usize,
) -> Result<(), Box<dyn Error>> {
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
        let (stream, _) = socket.accept().await?;

        if let Err(e) = workers.as_mut_slice()[c_worker].1.send(stream).await {
            error!("Could not enqueue stream into worker {}: {:?}", c_worker, e);
        }
        c_worker = (c_worker + 1) % num_workers;
    }
}
