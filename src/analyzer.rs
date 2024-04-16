use infer;
use std::collections::HashMap;

use std::fs::File;
use std::io::Error as IoError;

use std::path::{Path, PathBuf};
use tempfile::TempDir;
use yara::{Rules as YaraRules, YaraError};

use crate::analyzers::*;
use crate::inmem_file::{InMemFile, ReadAndSeek};
use crate::yara_rulset::YaraRuleset;

use tracing::{debug, error, info, span, Level};

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
}

wrap_err!(IoError, AnalyzerError);
wrap_err!(YaraError, AnalyzerError);
wrap_err_to_val!(yara::Error, YaraCrateError, AnalyzerError);

#[derive(Debug)]
pub enum Location {
    InMem(Vec<u8>),
    File(PathBuf),
}

#[derive(Debug)]
pub enum Sample {
    Mail(Vec<u8>),
    Raw(Vec<u8>),
    File {
        name: Option<String>,
        data: Location,
    },
}

impl Sample {
    pub fn get_fd<'a>(&'a self) -> Result<Box<dyn ReadAndSeek + 'a>, IoError> {
        Ok(match self {
            Sample::Mail(mem) => Box::new(InMemFile::new(mem)),
            Sample::Raw(mem) => Box::new(InMemFile::new(mem)),
            Sample::File {
                data: Location::InMem(mem),
                ..
            } => Box::new(InMemFile::new(mem)),
            Sample::File {
                data: Location::File(path),
                ..
            } => Box::new(File::open(path)?),
        })
    }
}

#[derive(Debug)]
pub struct AnalysisResult {
    pub matched_yara_rules: Option<Vec<String>>,
}

pub struct SampleContext<'a> {
    pub yara_rules: &'a YaraRules,
    pub archive_passwords: &'a [String],
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

impl Analyzer {
    pub fn new(yara_rules_loc: &Path) -> Result<Self, AnalyzerError> {
        let yara_ruleset = YaraRuleset::new();
        yara_ruleset.update_yara_rules(yara_rules_loc)?;

        let mut sample_analyzers: HashMap<Option<String>, AnalyzeFn> = HashMap::new();

        ZipAnalyzer::mime_types().iter().for_each(|m| {
            sample_analyzers.insert(Some((*m).to_string()), ZipAnalyzer::analyze);
        });

        sample_analyzers.insert(None, RawAnalyzer::analyze);

        Ok(Analyzer {
            yara_ruleset,
            sample_analyzers,
        })
    }

    pub fn analyze(&self, sample: Sample) -> Result<Vec<AnalysisResult>, AnalyzerError> {
        let c_span = span!(Level::DEBUG, "analyze_raw");
        let _guard = c_span.entered();

        let rules_lock = self.yara_ruleset.get_current_rules();

        let mut scan_results: Vec<AnalysisResult> = Vec::new();

        let mut tempdir_stack: Vec<TempDir> = Vec::new();
        let mut scan_stack: Vec<Sample> = Vec::new();
        scan_stack.push(sample);

        while !scan_stack.is_empty() {
            let sample = scan_stack.pop().unwrap();
            match &sample {
                Sample::Mail(mem) | Sample::Raw(mem) => {
                    info!("Popped sample: {:?}", &mem[0..mem.len().min(16)]);
                }
                Sample::File { name, .. } => {
                    info!("Popped Sample::File{{name: \"{:?}\", ..}}", name);
                }
            }

            let sample_type = match &sample {
                Sample::Mail(mem) => infer::get(&mem),
                Sample::Raw(mem) => infer::get(&mem),
                Sample::File {
                    data: Location::InMem(mem),
                    ..
                } => infer::get(&mem),
                Sample::File {
                    data: Location::File(path),
                    ..
                } => infer::get_from_path(path)?,
            };
            let sample_type_str = sample_type.map(|s| s.mime_type().to_string());

            info!("sample type: {:?}", sample_type_str);

            let unpacking_loc = TempDir::new()?;
            debug!("Created new unpacking location: {:?}", unpacking_loc.path());
            let context = SampleContext {
                yara_rules: rules_lock.as_ref().unwrap(),
                archive_passwords: &[],
                unpacking_location: unpacking_loc.path(),
            };

            if let Some(analyzer) = self.sample_analyzers.get(&sample_type_str) {
                match analyzer(&sample, &context) {
                    Ok((r, dropped_samples)) => {
                        debug!("{:?}-analyzer returned: {:?}", sample_type_str, r);
                        if let Some(dropped_samples) = dropped_samples {
                            scan_stack.extend(dropped_samples);
                        }
                        scan_results.push(r);
                    }
                    Err(e) => {
                        error!(
                            "{:?}-analyzer failed to analyze {:?}: {:?}",
                            sample_type_str, sample, e
                        );
                    }
                }
            } else {
                error!("No analyzer for \"{:?}\" found!", sample_type_str);
            }

            tempdir_stack.push(unpacking_loc);
        }

        Ok(scan_results)
    }
}
