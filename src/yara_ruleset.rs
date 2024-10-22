use std::{
    collections::HashMap,
    path::Path,
    str::FromStr,
    sync::{atomic::AtomicUsize, RwLock},
};

use reqwest::header::{HeaderMap, HeaderName, HeaderValue, InvalidHeaderName, InvalidHeaderValue};
use std::io::Read;
use yara::{Compiler, Rules as YaraRules};
use zip::ZipArchive;

use crate::{analyzer::AnalyzerError, inmem_file::InMemFile};
use log::{debug, error, info};

pub struct YaraRuleset {
    pos: AtomicUsize,
    yara_rules_db: [RwLock<Option<YaraRules>>; 2],
}

impl YaraRuleset {
    pub fn new() -> Self {
        YaraRuleset {
            pos: AtomicUsize::new(0),
            yara_rules_db: [RwLock::new(None), RwLock::new(None)],
        }
    }

    pub fn update_yara_rules(
        &self,
        yara_rules_loc: &Path,
        yara_http_urls: Option<Vec<String>>,
    ) -> Result<(), AnalyzerError> {
        let mut compiler: Compiler = Compiler::new()?;

        if yara_rules_loc.is_file() {
            debug!("Reading yara rules from {}", yara_rules_loc.display());
            compiler = compiler.add_rules_file(yara_rules_loc)?;
        } else {
            for p in std::fs::read_dir(yara_rules_loc)? {
                let p = p?.path();

                debug!("Reading yara rules from {}", p.display());
                if p.is_file() && matches!(p.extension().map(|s| s.to_str()), Some(Some("yar"))) {
                    compiler = compiler.add_rules_file(p)?;
                }
            }
        }

        if let Some(urls) = yara_http_urls {
            for url in urls {
                info!("Fetching rules from {}", &url);
                compiler =
                    compiler.add_rules_str(YaraHTTPFetcher::fetch_all(url.as_str())?.as_str())?;
            }
        }

        let yara_rules = compiler.compile_rules()?;

        info!("#rules: {}", yara_rules.get_rules().len());

        let new_pos = self.pos.load(std::sync::atomic::Ordering::Acquire) ^ 1;

        let mut d = self.yara_rules_db[new_pos]
            .write()
            .expect("Failed to get lock");

        *d = Some(yara_rules);

        self.pos
            .store(new_pos, std::sync::atomic::Ordering::Release);
        Ok(())
    }

    pub fn get_current_rules(&self) -> std::sync::RwLockReadGuard<'_, Option<YaraRules>> {
        let pos = self.pos.load(std::sync::atomic::Ordering::Acquire);

        self.yara_rules_db[pos].read().unwrap()
    }
}

struct YaraHTTPFetcher();

impl YaraHTTPFetcher {
    fn fetch_all(url: &str) -> Result<String, AnalyzerError> {
        let resp = reqwest::blocking::get(url)?;

        let content_type = match resp.headers().get("Content-Type") {
            Some(h) => h.to_str().map_err(|_| AnalyzerError::InvalidYaraType)?,
            None => {
                return Err(AnalyzerError::InvalidYaraType);
            }
        };

        info!("Content-Type: {}", content_type);

        match content_type.to_lowercase().as_str() {
            "application/zip"
            | "application/x-bzip"
            | "application/x-bzip2"
            | "application/octet-stream"
                if url.to_lowercase().ends_with(".zip") =>
            {
                Self::get_rules_from_zip(&resp.bytes()?)
            }
            "application/yara" | "text/plain" => Ok(resp.text()?),
            _ => Err(AnalyzerError::InvalidYaraType),
        }
    }

    fn get_rules_from_zip(buf: &[u8]) -> Result<String, AnalyzerError> {
        let fd = InMemFile::new(buf);

        let mut rules = String::new();

        let mut archive = match ZipArchive::new(fd) {
            Ok(z) => z,
            Err(e) => {
                error!("Could not open content as zip! {:?}", e);
                return Err(AnalyzerError::InvalidYaraType);
            }
        };

        for fileid in 0..archive.len() {
            match archive.by_index(fileid) {
                Ok(mut file) => {
                    if file.is_dir() {
                        continue;
                    }

                    if !file.name().ends_with(".yar") {
                        info!("Skipping {}, since it ends not with .yar", file.name());
                        continue;
                    }

                    let mut file_data = Vec::new();
                    if file.read_to_end(&mut file_data).is_ok() {
                        let file_data = match String::from_utf8(file_data) {
                            Ok(f) => f,
                            Err(e) => {
                                error!("Failed to utf-8 decode file: {}: {:?}", file.name(), e);
                                continue;
                            }
                        };
                        rules.push_str(&file_data);
                    }
                }
                Err(e) => {
                    error!("Could not unpack file: {:?}", e);
                }
            }
        }

        Ok(rules)
    }
}

#[derive(Debug)]
pub enum ToHeaderMapError {
    InvalidHeaderName,
    InvalidHeaderValue,
}

macro_rules! to_err {
    ($t:ident, $e:ident) => {
        impl From<$e> for $t {
            fn from(_: $e) -> $t {
                $t::$e
            }
        }
    };
}

to_err!(ToHeaderMapError, InvalidHeaderName);
to_err!(ToHeaderMapError, InvalidHeaderValue);

#[allow(unused)]
trait ToHeaderMap {
    fn to_headermap(&self) -> Result<HeaderMap, ToHeaderMapError>;
}

impl ToHeaderMap for HashMap<String, String> {
    fn to_headermap(&self) -> Result<HeaderMap, ToHeaderMapError> {
        let mut map = HeaderMap::new();
        for (k, v) in self.iter() {
            map.append(&HeaderName::from_str(k)?, HeaderValue::from_str(v)?);
        }

        Ok(map)
    }
}
