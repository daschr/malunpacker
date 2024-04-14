use infer;
use std::collections::HashMap;

use std::fs::File;
use std::io::{Error as IoError, SeekFrom};
use std::io::{IoSlice, Read, Seek};

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicUsize;
use std::sync::RwLock;
use tempfile::TempDir;
use yara::{Compiler, IoErrorKind, Rules as YaraRules, Scanner, YaraError};

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

struct YaraRuleset {
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

    pub fn update_yara_rules(&self, yara_rules_loc: &PathBuf) -> Result<(), AnalyzerError> {
        let compiler: Compiler = Compiler::new()?;
        let compiler = compiler.add_rules_file(yara_rules_loc)?;

        let yara_rules = compiler.compile_rules()?;

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

#[derive(Debug)]
enum Location {
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
    matched_yara_rules: Option<Vec<String>>,
}

pub struct SampleContext<'a> {
    yara_rules: &'a YaraRules,
    archive_passwords: &'a [String],
    unpacking_location: &'a Path,
}

type AnalyzeFn = fn(
    sample: &Location,
    context: &SampleContext,
) -> Result<(AnalysisResult, Option<Vec<Location>>), AnalyzerError>;

trait Analyze {
    fn analyze(
        sample: &Location,
        context: &SampleContext,
    ) -> Result<(AnalysisResult, Option<Vec<Location>>), AnalyzerError>;
    fn mime_types() -> &'static [&'static str];
}

struct ZipAnalyzer();

impl Analyze for ZipAnalyzer {
    fn analyze(
        sample: &Location,
        context: &SampleContext,
    ) -> Result<(AnalysisResult, Option<Vec<Location>>), AnalyzerError> {
        let len = match &sample {
            Location::InMem(m) => m.len(),
            Location::File(path) => {
                let fd = File::open(path)?;

                fd.metadata()?.len() as usize
            }
        };

        match &sample {
            Location::InMem(m) => {
                sevenz_rust::decompress(InMemFile::new(&m), context.unpacking_location)
                    .map_err(|e| AnalyzerError::Other(e.into()))?;
            }
            Location::File(path) => {
                sevenz_rust::decompress_file(path, context.unpacking_location)?;
            }
        }

        let mut scanner = context.yara_rules.scanner()?;
        let found_rules: Vec<String> = match sample {
            Location::InMem(data) => scanner.scan_mem(&data)?,
            Location::File(path) => scanner.scan_file(path)?,
        }
        .iter()
        .map(|r| r.identifier.to_string())
        .collect();

        Ok((
            AnalysisResult {
                matched_yara_rules: if found_rules.is_empty() {
                    None
                } else {
                    Some(found_rules)
                },
            },
            None,
        ))
    }

    fn mime_types() -> &'static [&'static str] {
        &[
            "application/x-7z-compressed",
            "application/zip",
            "application/x-bzip",
            "application/x-bzip2",
        ]
    }
}

struct RawAnalyzer();

impl Analyze for RawAnalyzer {
    fn analyze(
        sample: &Location,
        context: &SampleContext,
    ) -> Result<(AnalysisResult, Option<Vec<Location>>), AnalyzerError> {
        let mut scanner = context.yara_rules.scanner()?;

        let found_rules: Vec<String> = match sample {
            Location::InMem(data) => scanner.scan_mem(&data)?,
            Location::File(path) => scanner.scan_file(path)?,
        }
        .iter()
        .map(|r| r.identifier.to_string())
        .collect();

        Ok((
            AnalysisResult {
                matched_yara_rules: if found_rules.is_empty() {
                    None
                } else {
                    Some(found_rules)
                },
            },
            None,
        ))
    }

    fn mime_types() -> &'static [&'static str] {
        &[]
    }
}

pub struct InMemFile<'a> {
    pos: u64,
    buf: &'a [u8],
}

impl<'a> InMemFile<'a> {
    fn new(buf: &'a [u8]) -> Self {
        InMemFile { pos: 0, buf }
    }
}

impl<'a> Seek for InMemFile<'a> {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        match pos {
            SeekFrom::Start(offset) => {
                if offset > self.buf.len() as u64 {
                    return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, ""));
                }
                self.pos = offset as u64;
                Ok(offset)
            }
            SeekFrom::End(_) => Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "")),
            SeekFrom::Current(offset) => {
                if (self.pos as i64 + offset) as u64 > self.buf.len() as u64 {
                    return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, ""));
                }
                self.pos += (self.pos as i64 + offset) as u64;
                Ok(self.pos)
            }
        }
    }
}

impl<'a> Read for InMemFile<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let l = (self.buf.len() - self.pos as usize).min(buf.len());
        buf.copy_from_slice(&self.buf[self.pos as usize..self.pos as usize + l]);

        Ok(l)
    }
}
