use std::collections::HashMap;

use std::fs::File;
use std::io::Error as IoError;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use tempfile::TempDir;
use yara::{Rules as YaraRules, YaraError};

use crate::analyzers::*;
use crate::inmem_file::{InMemFile, ReadAndSeek};
use crate::yara_ruleset::YaraRuleset;

use magic::cookie::DatabasePaths;
use magic::Cookie as MagicCookie;
use tracing::{debug, error, info};

macro_rules! wrap_err {
    ($err:ident, $enum:ident) => {
        impl From<$err> for $enum {
            fn from(value: $err) -> Self {
                $enum::$err(value)
            }
        }
    };
}

macro_rules! wrap_err_to_val {
    ($err:ty, $val:ident, $enum:ident) => {
        impl From<$err> for $enum {
            fn from(value: $err) -> Self {
                $enum::$val(value)
            }
        }
    };
}

#[derive(Debug, thiserror::Error)]
pub enum AnalyzerError {
    #[error("Other error")]
    Other(Box<dyn std::error::Error>),
    #[error("IoError")]
    IoError(IoError),
    #[error("YaraError")]
    YaraError(YaraError),
    #[error("YaraError2")]
    YaraCrateError(yara::Error),
    #[error("InvalidSample")]
    InvalidSample,
}

wrap_err!(IoError, AnalyzerError);
wrap_err!(YaraError, AnalyzerError);
wrap_err_to_val!(yara::Error, YaraCrateError, AnalyzerError);
wrap_err_to_val!(Box<dyn std::error::Error>, Other, AnalyzerError);

impl From<magic::cookie::OpenError> for AnalyzerError {
    fn from(value: magic::cookie::OpenError) -> Self {
        AnalyzerError::Other(Box::new(value))
    }
}

impl From<magic::cookie::Error> for AnalyzerError {
    fn from(value: magic::cookie::Error) -> Self {
        AnalyzerError::Other(Box::new(value))
    }
}

impl From<anyhow::Error> for AnalyzerError {
    fn from(value: anyhow::Error) -> Self {
        AnalyzerError::Other(value.into())
    }
}

#[derive(Debug)]
pub enum Location {
    InMem(Vec<u8>),
    File(PathBuf),
}

#[derive(Debug)]
pub struct Sample {
    pub name: Option<String>,
    pub data: Location,
    pub unpacking_creds: Option<Arc<Vec<String>>>,
}

impl Sample {
    pub fn get_fd<'a>(&'a self) -> Result<Box<dyn ReadAndSeek + 'a>, IoError> {
        Ok(match &self.data {
            Location::InMem(mem) => Box::new(InMemFile::new(mem.as_slice())),
            Location::File(path) => Box::new(File::open(path)?),
        })
    }
}

#[allow(unused)]
#[derive(Debug)]
pub struct AnalysisResult {
    pub sample_id: Option<String>,
    pub matched_yara_rules: Option<Vec<String>>,
}

pub struct SampleContext<'a> {
    pub yara_rules: &'a YaraRules,
    pub unpacking_location: &'a Path,
}

pub type AnalyzeFn = fn(
    sample: &Sample,
    context: &SampleContext,
) -> Result<(AnalysisResult, Option<Vec<Sample>>), AnalyzerError>;

pub trait Analyze {
    fn analyze(
        sample: &Sample,
        context: &SampleContext,
    ) -> Result<(AnalysisResult, Option<Vec<Sample>>), AnalyzerError>;
    fn mime_types() -> &'static [&'static str];
}

pub struct Analyzer {
    yara_ruleset: YaraRuleset,
    sample_analyzers: HashMap<Option<String>, AnalyzeFn>,
}

macro_rules! register_analyzer {
    ($map:expr, $analyzer:ident) => {
        $analyzer::mime_types().iter().for_each(|m| {
            ($map).insert(Some((*m).to_string()), $analyzer::analyze);
        });
    };
}
impl Analyzer {
    pub fn new(yara_rules_loc: &Path) -> Result<Self, AnalyzerError> {
        let yara_ruleset = YaraRuleset::new();
        yara_ruleset.update_yara_rules(yara_rules_loc)?;

        let mut sample_analyzers: HashMap<Option<String>, AnalyzeFn> = HashMap::new();

        register_analyzer!(&mut sample_analyzers, SevenZAnalyzer);
        register_analyzer!(&mut sample_analyzers, ZipAnalyzer);
        register_analyzer!(&mut sample_analyzers, RarAnalyzer);
        register_analyzer!(&mut sample_analyzers, MailAnalyzer);
        register_analyzer!(&mut sample_analyzers, Iso9660Analyzer);

        sample_analyzers.insert(None, RawAnalyzer::analyze);

        Ok(Analyzer {
            yara_ruleset,
            sample_analyzers,
        })
    }

    pub fn analyze(
        &self,
        sample: Sample,
        forced_mime_type: Option<&str>,
    ) -> Result<Vec<AnalysisResult>, AnalyzerError> {
        let cookie = MagicCookie::open(magic::cookie::Flags::MIME_TYPE)?;
        let db_paths: DatabasePaths = Default::default();
        let magic_cookie = cookie.load(&db_paths).expect("Could not load database");

        let rules_lock = self.yara_ruleset.get_current_rules();

        let mut scan_results: Vec<AnalysisResult> = Vec::new();

        let mut tempdir_stack: Vec<TempDir> = Vec::new();
        let mut scan_stack: Vec<Sample> = Vec::new();
        scan_stack.push(sample);
        let mut first_sample = true;

        while let Some(sample) = scan_stack.pop() {
            match &sample.data {
                Location::InMem(mem) => {
                    info!(
                        "Popped sample Sample {{ name: {:?}, data: {:x?} }}",
                        sample.name,
                        &mem[0..mem.len().min(16)]
                    );
                }
                Location::File(path) => {
                    info!(
                        "Popped sample Sample {{ name: {:?}, data: {:?} }}",
                        sample.name, path
                    );
                }
            }

            let sample_type_str: Option<String> = {
                let r = match &sample.data {
                    Location::InMem(mem) => magic_cookie.buffer(mem),
                    Location::File(path) => magic_cookie.file(path),
                }
                .map_or_else(|_| None, Some);

                if first_sample {
                    first_sample = false;
                    match forced_mime_type {
                        Some(t) => Some(t.to_string()),
                        None => r,
                    }
                } else {
                    r
                }
            };

            info!("sample type: {:?}", sample_type_str);

            let unpacking_loc = TempDir::new()?;
            // debug!("Created new unpacking location: {:?}", unpacking_loc.path());
            let context = SampleContext {
                yara_rules: rules_lock.as_ref().unwrap(),
                unpacking_location: unpacking_loc.path(),
            };

            let analyzer = match self.sample_analyzers.get(&sample_type_str) {
                Some(ana) => ana,
                None => {
                    info!(
                        "No analyzer for {:?} found, using default one!",
                        sample_type_str
                    );

                    self.sample_analyzers.get(&None).unwrap()
                }
            };

            match analyzer(&sample, &context) {
                Ok((r, dropped_samples)) => {
                    debug!("analyzer for {:?} returned: {:?}", sample_type_str, r);
                    if let Some(dropped_samples) = dropped_samples {
                        scan_stack.extend(dropped_samples);
                    }
                    scan_results.push(r);
                }
                Err(e) => {
                    error!(
                        "analyzer for {:?} failed to analyze {:?}: {:?}",
                        sample_type_str, sample, e
                    );
                }
            }
            tempdir_stack.push(unpacking_loc);
        }

        Ok(scan_results)
    }
}
