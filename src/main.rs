mod acpi_api;
mod analyzer;
mod analyzers;
mod filelister;
mod inmem_file;
mod yara_rulset;
// mod http_api;

use acpi_api::ICAPWorker;
use std::{env, error::Error, net::SocketAddr};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();

    let listen_addr = if args.len() > 1 {
        args[1]
            .parse::<SocketAddr>()
            .expect("Could not parse SocketAddr")
    } else {
        "0.0.0.0:8000".parse::<SocketAddr>().unwrap()
    };

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
