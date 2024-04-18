use crate::analyzer::{AnalysisResult, Analyze, AnalyzerError, Location, Sample, SampleContext};
use crate::filelister;
use libcdio_sys::{
    _cdio_list_begin, _cdio_list_free, _cdio_list_node_data, _cdio_list_node_next, iso9660_close,
    iso9660_ifs_readdir, iso9660_iso_seek_read, iso9660_open, iso9660_stat_free,
    iso9660_stat_s__STAT_DIR, iso9660_stat_s__STAT_FILE, iso9660_stat_t, iso9660_t,
    iso_enum1_s_ISO_BLOCKSIZE,
};
use mail_parser::{MessageParser, MimeHeaders};
use sevenz_rust::{decompress_with_password, Password};
use std::ffi::{c_void, CStr, CString};
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
                let sample_list = filelister::list_files(context.unpacking_location, |p| Sample {
                    name: p.to_str().map(|s| String::from(s)),
                    data: Location::File(p),
                    unpacking_creds: None,
                })?;

                info!("dropped samples: {:?}", sample_list);
                if !sample_list.is_empty() {
                    dropped_samples = Some(sample_list);
                }
            }
            Err(sevenz_rust::Error::PasswordRequired) => {
                warn!("{:?} needs a password", sample);

                if let Some(unpacking_creds) = &sample.unpacking_creds {
                    for pw in unpacking_creds.as_slice() {
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
                                filelister::list_files(context.unpacking_location, |p| Sample {
                                    name: p.to_str().map(|s| String::from(s)),
                                    data: Location::File(p),
                                    unpacking_creds: None,
                                })?;

                            if sample_list.is_empty() {
                                dropped_samples = Some(sample_list);
                            }
                            break;
                        }
                    }
                }
            }
            Err(e) => {
                error!("Could not unpack sample: {:?}", e);
            }
        }

        let mut scanner = context.yara_rules.scanner()?;

        let found_rules: Vec<String> = match &sample.data {
            Location::InMem(mem) => scanner.scan_mem(mem)?,
            Location::File(path) => scanner.scan_file(path)?,
        }
        .iter()
        .map(|r| r.identifier.to_string())
        .collect();

        let sample_id: Option<String> = sample.name.clone();

        Ok((
            AnalysisResult {
                sample_id,
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
                                Ok(_) => dropped_samples.push(Sample {
                                    name: Some(file.name().to_string()),
                                    data: Location::InMem(file_data),
                                    unpacking_creds: None,
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
                        if let Some(unpacking_creds) = &sample.unpacking_creds {
                            for pw in unpacking_creds.as_slice() {
                                match (&mut archive).by_index_decrypt(fileid, pw.as_bytes()) {
                                    Ok(Ok(mut file)) => {
                                        info!(
                                            "Would unpack '{}' with password '{}'",
                                            file.name(),
                                            pw
                                        );

                                        let mut file_data = Vec::new();
                                        match file.read_to_end(&mut file_data) {
                                            Ok(_) => dropped_samples.push(Sample {
                                                name: Some(file.name().to_string()),
                                                data: Location::InMem(file_data),
                                                unpacking_creds: None,
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
                                    | Err(ZipError::UnsupportedArchive(
                                        ZipError::PASSWORD_REQUIRED,
                                    )) => (),
                                    Err(e) => {
                                        error!("Could not unpack sample: {:?}", e);
                                        break;
                                    }
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

        let sample_id: Option<String> = sample.name.clone();

        let found_rules: Vec<String> = match &sample.data {
            Location::InMem(mem) => scanner.scan_mem(mem)?,
            Location::File(path) => scanner.scan_file(path)?,
        }
        .iter()
        .map(|r| r.identifier.to_string())
        .collect();

        Ok((
            AnalysisResult {
                sample_id,
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
        let c_span = span!(Level::DEBUG, "RawAnalyzer");
        let _guard = c_span.enter();

        let mut scanner = context.yara_rules.scanner()?;

        let found_rules: Vec<String> = match &sample.data {
            Location::InMem(mem) => scanner.scan_mem(mem)?,
            Location::File(path) => scanner.scan_file(path)?,
        }
        .iter()
        .map(|r| r.identifier.to_string())
        .collect();

        let sample_id: Option<String> = sample.name.clone();

        Ok((
            AnalysisResult {
                sample_id,
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

pub struct MailAnalyzer();

impl Analyze for MailAnalyzer {
    fn analyze(
        sample: &Sample,
        context: &SampleContext,
    ) -> Result<(AnalysisResult, Option<Vec<Sample>>), AnalyzerError> {
        let mail_content = match &sample.data {
            Location::InMem(mem) => mem.clone(),
            Location::File(path) => std::fs::read(path)?,
        };

        let mail = match MessageParser::default().parse(mail_content.as_slice()) {
            Some(m) => m,
            None => {
                return Err(AnalyzerError::InvalidSample);
            }
        };

        let mut dropped_samples: Vec<Sample> = Vec::new();
        for (i, attachment) in mail.attachments().enumerate() {
            info!("attachment {}: {:?}", i, attachment.attachment_name());
            dropped_samples.push(Sample {
                name: attachment.attachment_name().map(|s| s.to_string()),
                data: Location::InMem(Vec::from(attachment.contents())),
                unpacking_creds: None,
            });
        }

        let mut scanner = context.yara_rules.scanner()?;

        let found_rules: Vec<String> = match &sample.data {
            Location::InMem(mem) => scanner.scan_mem(mem)?,
            Location::File(path) => scanner.scan_file(path)?,
        }
        .iter()
        .map(|r| r.identifier.to_string())
        .collect();

        let sample_id: Option<String> = sample.name.clone();

        Ok((
            AnalysisResult {
                sample_id,
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
        &["message/rfc822"]
    }
}

pub struct Iso9660Analyzer();

impl Iso9660Analyzer {
    unsafe fn fetch_all_iso_files(p_iso: *mut iso9660_t) -> Result<Vec<Sample>, AnalyzerError> {
        let c_span = span!(Level::DEBUG, "fetch_all_iso_files");
        let _guard = c_span.enter();

        let mut dropped_samples: Vec<Sample> = Vec::new();

        let mut dir_stack: Vec<String> = Vec::new();
        dir_stack.push(String::from("/"));

        while !dir_stack.is_empty() {
            let cur_dir = dir_stack.pop().unwrap();
            let c_cur_dir = CString::new(cur_dir.as_str()).unwrap();

            let raw_list = iso9660_ifs_readdir(p_iso, c_cur_dir.as_ptr());

            if raw_list.is_null() {
                error!("Could not read dir: {:?}", cur_dir);
                break;
            }

            let mut c_node = _cdio_list_begin(raw_list);
            while !c_node.is_null() {
                let node_stat = &mut *(_cdio_list_node_data(c_node) as *mut iso9660_stat_t);

                let filename = CStr::from_ptr(node_stat.filename.as_ptr());
                info!("filename: {:?}", filename);
                match node_stat.type_ {
                    #[allow(non_upper_case_globals)]
                    iso9660_stat_s__STAT_DIR => {
                        let str_filename = filename.to_str().unwrap();
                        if str_filename != "." && str_filename != ".." {
                            info!("'{}' is a directory", str_filename);
                            let mut fp_filename = cur_dir.clone();
                            fp_filename.push_str("/");
                            fp_filename.push_str(str_filename);

                            info!("at here2");
                            dir_stack.push(fp_filename);
                            info!("at here");
                        }
                    }
                    #[allow(non_upper_case_globals)]
                    iso9660_stat_s__STAT_FILE => {
                        info!("{:?} is a file", filename);
                        if let Some(sample) = Self::read_sample_from_iso(p_iso, node_stat) {
                            dropped_samples.push(sample);
                        }
                    }
                    _ => {
                        error!("unkown node_type: {}", node_stat.type_);
                    }
                }

                iso9660_stat_free(node_stat);
                c_node = _cdio_list_node_next(c_node)
            }

            _cdio_list_free(raw_list, true as i32, None);
        }

        Ok(dropped_samples)
    }

    unsafe fn read_sample_from_iso(
        p_iso: *mut iso9660_t,
        file_stat: &mut iso9660_stat_t,
    ) -> Option<Sample> {
        let c_span = span!(Level::DEBUG, "read_sample_from_iso");
        let _guard = c_span.enter();

        let filename = CStr::from_ptr(file_stat.filename.as_mut_ptr());

        let mut file_data: Vec<u8> = Vec::new();
        let mut read_bytes = 0usize;

        let mut buf = [0u8; iso_enum1_s_ISO_BLOCKSIZE as usize];

        while read_bytes < file_stat.size as usize {
            let n_bytes_read = iso9660_iso_seek_read(
                p_iso,
                buf.as_mut_ptr() as *mut c_void,
                file_stat.lsn + (read_bytes as u32 / iso_enum1_s_ISO_BLOCKSIZE) as i32,
                1,
            );
            if n_bytes_read == 0 {
                error!(
                    "Failed to read bytes for file {:?}, num already read: {}",
                    filename, read_bytes
                );
            }
            file_data.extend_from_slice(&buf[0..n_bytes_read as usize]);
            read_bytes += n_bytes_read as usize;
        }

        Some(Sample {
            name: filename.to_str().ok().map(|s| s.to_string()),
            data: Location::InMem(file_data),
            unpacking_creds: None,
        })
    }
}

impl Analyze for Iso9660Analyzer {
    fn analyze(
        sample: &Sample,
        context: &SampleContext,
    ) -> Result<(AnalysisResult, Option<Vec<Sample>>), AnalyzerError> {
        let c_span = span!(Level::DEBUG, "Iso9660Analyzer");
        let _guard = c_span.enter();

        let mut scanner = context.yara_rules.scanner()?;

        let found_rules: Vec<String> = match &sample.data {
            Location::InMem(mem) => scanner.scan_mem(mem)?,
            Location::File(path) => scanner.scan_file(path)?,
        }
        .iter()
        .map(|r| r.identifier.to_string())
        .collect();

        let sample_id: Option<String> = sample.name.clone();

        let iso_path = match &sample.data {
            Location::InMem(mem) => {
                let mut iso_path = context.unpacking_location.to_path_buf();
                iso_path.push("sample.iso");

                std::fs::write(iso_path.as_path(), mem)?;

                iso_path
            }
            Location::File(path) => path.to_path_buf(),
        };
        let iso = unsafe {
            let c_iso_path = CString::new(iso_path.to_str().unwrap()).unwrap();
            iso9660_open(c_iso_path.as_ptr())
        };

        if iso.is_null() {
            error!("Failed to open {:?} as an ISO!", &iso_path);
            return Ok((
                AnalysisResult {
                    sample_id,
                    matched_yara_rules: if found_rules.is_empty() {
                        None
                    } else {
                        Some(found_rules)
                    },
                },
                None,
            ));
        }

        let dropped_samples = unsafe { Iso9660Analyzer::fetch_all_iso_files(iso).ok() };

        unsafe { iso9660_close(iso) };

        Ok((
            AnalysisResult {
                sample_id,
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
        &["application/x-iso9660-image"]
    }
}
