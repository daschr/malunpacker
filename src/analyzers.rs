use crate::analyzer::{AnalysisResult, Analyze, AnalyzerError, Location, Sample, SampleContext};
use crate::filelister;
use sevenz_rust::{decompress_with_password, Password};
use std::io::Read;
use tracing::{debug, error, info, span, warn, Level};
use zip::{result::ZipError, ZipArchive};

pub struct SevenZAnalyzer();

impl Analyze for SevenZAnalyzer {
    fn analyze(
        sample: &Sample,
        context: &SampleContext,
    ) -> Result<(AnalysisResult, Option<Vec<Sample>>), AnalyzerError> {
        let mut sample_source = sample.get_fd()?;

        let c_span = span!(Level::DEBUG, "SevenZAnalyzer");
        let _guard = c_span.enter();

        info!("scanning {:?}", sample);
        let mut dropped_samples: Option<Vec<Sample>> = None;

        match decompress_with_password(
            &mut sample_source,
            context.unpacking_location,
            Password::empty(),
        ) {
            Ok(_) => {
                info!("successfully unpacked with empty password");
                let sample_list =
                    filelister::list_files(context.unpacking_location, |p| Sample::File {
                        name: p.to_str().map(|s| String::from(s)),
                        data: Location::File(p),
                    })?;

                info!("dropped samples: {:?}", sample_list);
                if !sample_list.is_empty() {
                    dropped_samples = Some(sample_list);
                }
            }
            Err(sevenz_rust::Error::PasswordRequired) => {
                warn!("{:?} needs a password", sample);
                for pw in context.archive_passwords {
                    if let Ok(()) = decompress_with_password(
                        &mut sample_source,
                        context.unpacking_location,
                        Password::from(pw.as_str()),
                    ) {
                        info!(
                            "successfully unpacked {:?} using password '{}'",
                            sample,
                            pw.as_str()
                        );

                        let sample_list =
                            filelister::list_files(context.unpacking_location, |p| Sample::File {
                                name: p.to_str().map(|s| String::from(s)),
                                data: Location::File(p),
                            })?;

                        if sample_list.is_empty() {
                            dropped_samples = Some(sample_list);
                        }
                        break;
                    }
                }
            }
            Err(e) => {
                error!("Could not unpack sample: {:?}", e);
            }
        }

        let mut scanner = context.yara_rules.scanner()?;

        let found_rules: Vec<String> = match sample {
            Sample::Mail(mem)
            | Sample::Raw(mem)
            | Sample::File {
                data: Location::InMem(mem),
                ..
            } => scanner.scan_mem(mem)?,
            Sample::File {
                data: Location::File(path),
                ..
            } => scanner.scan_file(path)?,
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
            "application/x-bzip",
            "application/x-bzip2",
        ]
    }
}

pub struct ZipAnalyzer();

impl Analyze for ZipAnalyzer {
    fn analyze(
        sample: &Sample,
        context: &SampleContext,
    ) -> Result<(AnalysisResult, Option<Vec<Sample>>), AnalyzerError> {
        let c_span = span!(Level::DEBUG, "ZipAnalyzer");
        let _guard = c_span.enter();

        let sample_source = sample.get_fd()?;

        let mut dropped_samples: Vec<Sample> = Vec::new();

        match ZipArchive::new(sample_source) {
            Ok(mut archive) => {
                for fileid in 0..archive.len() {
                    let mut need_password = false;
                    match (&mut archive).by_index(fileid) {
                        Ok(mut file) => {
                            if file.is_dir() {
                                debug!("Skipping \"{}\", since it's a directory", file.name());
                                continue;
                            }

                            info!("Would unpack '{}'", file.name());
                            let mut file_data = Vec::new();
                            match file.read_to_end(&mut file_data) {
                                Ok(_) => dropped_samples.push(Sample::File {
                                    name: Some(file.name().to_string()),
                                    data: Location::InMem(file_data),
                                }),
                                Err(e) => {
                                    error!("Failed to read data for '{}': {:?}", file.name(), e);
                                }
                            }
                        }
                        Err(ZipError::UnsupportedArchive(ZipError::PASSWORD_REQUIRED)) => {
                            need_password = true;
                        }
                        Err(e) => {
                            error!("Could not unpack sample: {:?}", e);
                        }
                    }

                    if need_password {
                        for pw in context.archive_passwords {
                            match (&mut archive).by_index_decrypt(fileid, pw.as_bytes()) {
                                Ok(Ok(mut file)) => {
                                    info!("Would unpack '{}' with password '{}'", file.name(), pw);

                                    let mut file_data = Vec::new();
                                    match file.read_to_end(&mut file_data) {
                                        Ok(_) => dropped_samples.push(Sample::File {
                                            name: Some(file.name().to_string()),
                                            data: Location::InMem(file_data),
                                        }),
                                        Err(e) => {
                                            error!(
                                                "Failed to read data for '{}': {:?}",
                                                file.name(),
                                                e
                                            );
                                        }
                                    }
                                }
                                Ok(Err(_))
                                | Err(ZipError::UnsupportedArchive(ZipError::PASSWORD_REQUIRED)) => {
                                    ()
                                }
                                Err(e) => {
                                    error!("Could not unpack sample: {:?}", e);
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                error!("Could not open {:?} as a zip archive: {:?}", &sample, e);
            }
        }

        let mut scanner = context.yara_rules.scanner()?;

        let found_rules: Vec<String> = match sample {
            Sample::Mail(mem)
            | Sample::Raw(mem)
            | Sample::File {
                data: Location::InMem(mem),
                ..
            } => scanner.scan_mem(mem)?,
            Sample::File {
                data: Location::File(path),
                ..
            } => scanner.scan_file(path)?,
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
            Some(dropped_samples),
        ))
    }

    fn mime_types() -> &'static [&'static str] {
        &["application/zip"]
    }
}

pub struct RawAnalyzer();

impl Analyze for RawAnalyzer {
    fn analyze(
        sample: &Sample,
        context: &SampleContext,
    ) -> Result<(AnalysisResult, Option<Vec<Sample>>), AnalyzerError> {
        let mut scanner = context.yara_rules.scanner()?;

        let found_rules: Vec<String> = match sample {
            Sample::Mail(mem)
            | Sample::Raw(mem)
            | Sample::File {
                data: Location::InMem(mem),
                ..
            } => scanner.scan_mem(mem)?,
            Sample::File {
                data: Location::File(path),
                ..
            } => scanner.scan_file(path)?,
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
