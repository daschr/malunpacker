use infer::archive;
use sevenz_rust::Archive;

use crate::analyzer::{AnalysisResult, Analyze, AnalyzeFn, AnalyzerError, Location, SampleContext};
use crate::inmem_file::InMemFile;
use std::fs::File;
use std::io::{Read, Seek};

pub struct ZipAnalyzer();

trait ReadAndSeek: Read + Seek {}

impl<RS: Read + Seek> ReadAndSeek for RS {}

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

        let mut sample_source: Box<dyn ReadAndSeek> = match &sample {
            Location::InMem(mem) => Box::new(InMemFile::new(mem)),
            Location::File(path) => Box::new(File::open(path)?),
        };

        let mut dropped_samples = Vec::new();

        match Archive::read(&mut sample_source, len as u64, &[]) {
            Ok(archive) => archive.files,
            Err(sevenz_rust::Error::PasswordRequired) => {}
            Err(e) => {
                eprintln!("Could not unpack sample: {:?}", e);
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

pub struct RawAnalyzer();

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
