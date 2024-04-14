use crate::analyzer::{AnalysisResult, Analyze, AnalyzerError, Location, SampleContext};
use crate::filelister;
use crate::inmem_file::InMemFile;
use sevenz_rust::{decompress_with_password, Password};
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
        let mut sample_source: Box<dyn ReadAndSeek> = match &sample {
            Location::InMem(mem) => Box::new(InMemFile::new(mem)),
            Location::File(path) => Box::new(File::open(path)?),
        };

        let mut dropped_samples: Option<Vec<Location>> = None;

        match decompress_with_password(
            &mut sample_source,
            context.unpacking_location,
            Password::empty(),
        ) {
            Ok(_) => {
                let sample_list =
                    filelister::list_files(context.unpacking_location, |p| Location::File(p))?;

                if sample_list.is_empty() {
                    dropped_samples = Some(sample_list);
                }
            }
            Err(sevenz_rust::Error::PasswordRequired) => {
                for pw in context.archive_passwords {
                    if let Ok(()) = decompress_with_password(
                        &mut sample_source,
                        context.unpacking_location,
                        Password::from(pw.as_str()),
                    ) {
                        let sample_list =
                            filelister::list_files(context.unpacking_location, |p| {
                                Location::File(p)
                            })?;

                        if sample_list.is_empty() {
                            dropped_samples = Some(sample_list);
                        }
                        break;
                    }
                }
            }
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
            dropped_samples,
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
