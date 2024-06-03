use anyhow::Context;
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::from_utf8;
use std::{env, fs};
use tracing::{debug, span, Level};

#[allow(unused)]
#[derive(Deserialize)]
pub struct Config {
    pub icap_api_listen_addr: Option<SocketAddr>,
    pub icap_num_workers: Option<usize>,
    pub http_api_listen_addr: Option<SocketAddr>,
    pub yara_rules: PathBuf,
    pub sentry_endpoint_url: Option<String>,
}

trait FromEnv
where
    Self: Sized,
{
    fn from_env(key: &str) -> anyhow::Result<Option<Self>>;
}

macro_rules! impl_FromEnv {
    ($type:ident) => {
        impl FromEnv for $type {
            fn from_env(key: &str) -> anyhow::Result<Option<Self>> {
                if let Ok(v) = env::var(key) {
                    return Ok(Some(
                        v.parse::<Self>()
                            .context(format!("Failed to parse value of key {key}"))?,
                    ));
                }
                Ok(None)
            }
        }
    };
}

impl_FromEnv!(SocketAddr);
impl_FromEnv!(usize);

impl Config {
    pub fn read_from_file(file: &Path) -> anyhow::Result<Self> {
        let c_span = span!(Level::INFO, "read_from_file");
        let _g = c_span.enter();

        debug!("Reading Config from {:?}", file);
        let raw_data =
            fs::read(file).context(format!("Failed to read data from {}", file.display()))?;

        let conf_str = from_utf8(raw_data.as_slice()).context("Config file is not valid UTF-8")?;

        debug!("Config:\n{}", conf_str);
        let conf: Config = toml::from_str(conf_str).context("Could not parse config file")?;

        Ok(conf)
    }

    pub fn read_from_env() -> anyhow::Result<Self> {
        let conf = Config {
            icap_api_listen_addr: SocketAddr::from_env("ICAP_API_LISTEN_ADDR")?,
            icap_num_workers: usize::from_env("ICAP_NUM_WORKERS")?,
            http_api_listen_addr: SocketAddr::from_env("HTTP_API_LISTEN_ADDR")?,
            yara_rules: PathBuf::from(env::var("YARA_RULES").context("YARA_RULES not defined")?),
            sentry_endpoint_url: env::var("SENTRY_ENDPOINT_URL").ok(),
        };

        Ok(conf)
    }
}
