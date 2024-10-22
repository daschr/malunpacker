mod analyzer;
mod analyzers;
mod config;
mod credential_extractor;
mod filelister;
mod icap_api;
mod inmem_file;
mod yara_ruleset;

use sentry::ClientInitGuard;
use std::{
    process,
    sync::Arc,
    time::{Duration, SystemTime},
};
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
    let conf = if env::var("CONF_FROM_ENV").is_ok_and(|s| s.to_lowercase() == "true") {
        config::Config::read_from_env()?
    } else {
        if let Ok(conf_file) = env::var("CONF_FILE") {
            config::Config::read_from_file(PathBuf::from(conf_file).as_path())?
        } else {
            eprintln!("Missing config file (specify CONF_FILE) (or missed CONF_FROM_ENV=true)!");
            process::exit(1);
        }
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
            .with_ansi(false)
            .with_line_number(true)
            .init();
        None
    };

    let analyzer = Arc::new(Analyzer::new(
        conf.yara_rules.as_path(),
        conf.yara_http_urls,
    )?);

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
            conf.quarantine_location,
            conf.cleanup_age_hours
                .map(|h| Duration::from_secs(60 * 60 * h)),
        ))
        .expect("Failed to initialize tokio runtime");

    info!("Exited");
    Ok(())
}

async fn quarantine_cleanup(quarantine_location: PathBuf, cleanup_age: Duration) {
    loop {
        tokio::time::sleep(cleanup_age).await;

        if !quarantine_location.as_path().exists() {
            continue;
        }

        if let Ok(mut dir) = tokio::fs::read_dir(quarantine_location.as_path()).await {
            while let Ok(Some(entry)) = dir.next_entry().await {
                let metadata = match entry.metadata().await {
                    Ok(md) => md,
                    Err(_) => continue,
                };

                if !metadata.is_file() {
                    continue;
                }

                let modified = match metadata.modified() {
                    Ok(m) => m,
                    Err(_) => continue,
                };

                if let Ok(dur_diff) = SystemTime::now().duration_since(modified) {
                    if dur_diff > cleanup_age {
                        if let Err(e) = tokio::fs::remove_file(entry.path()).await {
                            error!("Failed to delete file {}: {:?}", entry.path().display(), e);
                        }

                        info!("Removed quarantine file {}", entry.path().display());
                    }
                }
            }
        }
    }
}

async fn run_icap(
    listen_addr: SocketAddr,
    analyzer: Arc<Analyzer>,
    num_workers: usize,
    quarantine_location: Option<PathBuf>,
    cleanup_age: Option<Duration>,
) -> Result<(), Box<dyn Error>> {
    let socket = tokio::net::TcpListener::bind(listen_addr)
        .await
        .expect("Could not open socket");

    let mut workers: Vec<(JoinHandle<()>, Sender<TcpStream>)> = Vec::new();

    for _ in 0..num_workers {
        let (tx, rx) = channel(100);

        let c_ana = analyzer.clone();
        let c_ql = quarantine_location.clone();
        let handle = tokio::spawn(async move {
            let mut worker = ICAPWorker::new(rx, c_ana.as_ref(), c_ql);
            worker.run().await;
        });

        workers.push((handle, tx));
    }

    if let (Some(ql), Some(ca)) = (quarantine_location, cleanup_age) {
        let c_ql = ql.clone();
        tokio::spawn(async move { quarantine_cleanup(c_ql, ca) });
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
