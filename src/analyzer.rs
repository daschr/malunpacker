use infer;
use std::collections::HashMap;

use std::io::Error as IoError;

use std::path::{Path, PathBuf};
use tempfile::TempDir;
use yara::{Rules as YaraRules, Scanner, YaraError};

use crate::analyzers::*;
use crate::yara_rulset::YaraRuleset;

pub enum Sample {
    Mail(Vec<u8>),
    Raw(Vec<u8>),
}

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

#[derive(Debug)]
pub enum AnalyzerError {
    Other(Box<dyn std::error::Error>),
    IoError(IoError),
    YaraError(YaraError),
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

pub struct Analyzer {
    yara_ruleset: YaraRuleset,
    sample_analyzers: HashMap<Option<String>, AnalyzeFn>,
}

impl Analyzer {
    pub fn new(yara_rules_loc: &PathBuf) -> Result<Self, AnalyzerError> {
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

    pub fn analyze(&self, sample: Sample) -> Result<AnalysisResult, AnalyzerError> {
        Ok(AnalysisResult {
            matched_yara_rules: None,
        })
    }

    pub fn analyze_raw(
        &self,
        raw_sample: Location,
        yara_scanner: &Scanner,
    ) -> Result<(), AnalyzerError> {
        let rules_lock = self.yara_ruleset.get_current_rules();
        let mut scanner = rules_lock.as_ref().unwrap().scanner()?;

        let mut scan_results: Vec<AnalysisResult> = Vec::new();

        let temp_dir = tempfile::tempdir().expect("Could not create a temporary directory");
        let mut tempdir_stack: Vec<TempDir> = Vec::new();
        let mut scan_stack: Vec<Location> = Vec::new();
        scan_stack.push(raw_sample);

        while !scan_stack.is_empty() {
            let sample = scan_stack.pop().unwrap();
            let sample_type = match &sample {
                Location::InMem(mem) => infer::get(&mem),
                Location::File(path) => infer::get_from_path(path)?,
            };
            let sample_type_str = sample_type.map(|s| s.mime_type().to_string());

            let unpacking_loc = TempDir::new()?;

            let context = SampleContext {
                yara_rules: rules_lock.as_ref().unwrap(),
                archive_passwords: &[String::new()],
                unpacking_location: unpacking_loc.path(),
            };

            if let Some(analyzer) = self.sample_analyzers.get(&sample_type_str) {
                match analyzer(&sample, &context) {
                    Ok(r) => {
                        println!("{:?}-analyzer returned: {:?}", sample_type_str, r);
                    }
                    Err(e) => {
                        eprintln!(
                            "{:?}-analyzer failed to analyze {:?}: {:?}",
                            sample_type_str, sample, e
                        );
                    }
                }
            } else {
            }

            tempdir_stack.push(unpacking_loc);
        }

        Ok(())
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
    sample: &Location,
    context: &SampleContext,
) -> Result<(AnalysisResult, Option<Vec<Location>>), AnalyzerError>;

pub trait Analyze {
    fn analyze(
        sample: &Location,
        context: &SampleContext,
    ) -> Result<(AnalysisResult, Option<Vec<Location>>), AnalyzerError>;
    fn mime_types() -> &'static [&'static str];
}
