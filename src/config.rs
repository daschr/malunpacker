use serde::Deserialize;
use std::error::Error;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::from_utf8;
use tracing::{debug, error, info, span, Level};

#[derive(Deserialize)]
pub struct Config {
    pub icap_api_listen_addr: Option<SocketAddr>,
    pub icap_num_workers: Option<usize>,
    pub http_api_listen_addr: Option<SocketAddr>,
    pub yara_rules_file: PathBuf,
}

impl Config {
    pub fn read_from_file(file: &Path) -> Result<Self, Box<dyn Error>> {
        let c_span = span!(Level::INFO, "read_from_file");
        let _g = c_span.enter();

        debug!("Reading Config from {:?}", file);
        let raw_data = fs::read(file)?;

        let conf_str = from_utf8(&raw_data.as_slice())?;

        debug!("Config:\n{}", conf_str);
        let conf: Config = toml::from_str(conf_str)?;

        Ok(conf)
    }
}
