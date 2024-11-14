use crate::analyzer::{AnalysisResult, Analyze, AnalyzerError, Location, Sample, SampleContext};
use crate::credential_extractor::CredentialExtractor;
use crate::filelister;
use anyhow::Context;
use bzip2::read::BzDecoder;
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
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::{env, fs};
use tracing::{debug, error, info, span, warn, Level};
use unrar::error::UnrarError;
use unrar::{Archive as RarArchive, OpenArchive};
use zip::{result::ZipError, ZipArchive};

pub struct SevenZAnalyzer();

impl Analyze for SevenZAnalyzer {
    fn analyze(
        sample: &Sample,
        context: &SampleContext,
    ) -> Result<(AnalysisResult, Option<Vec<Sample>>), AnalyzerError> {
        let mut sample_source = sample.get_fd()?;

        let _span = span!(Level::INFO, "SevenZAnalyzer").entered();

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
                    name: p.to_str().map(String::from),
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

                let mut successfully_decrypted = false;
                if let Some(unpacking_creds) = &sample.unpacking_creds {
                    for pw in unpacking_creds.as_slice() {
                        if decompress_with_password(
                            &mut sample_source,
                            context.unpacking_location,
                            Password::from(pw.as_str()),
                        )
                        .is_ok()
                        {
                            info!(
                                "successfully unpacked {:?} using password '{}'",
                                sample,
                                pw.as_str()
                            );

                            successfully_decrypted = true;

                            let sample_list =
                                filelister::list_files(context.unpacking_location, |p| Sample {
                                    name: p.to_str().map(String::from),
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

                if !successfully_decrypted {
                    warn!(
                        "Failed to decrypt password-protected sample {:?}, no password matches",
                        sample
                    );
                }
            }
            Err(e) => {
                error!("Could not unpack sample {:?}: {:?}", sample, e);
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
        &["application/x-7z-compressed"]
    }
}

pub struct ZipAnalyzer();

impl Analyze for ZipAnalyzer {
    fn analyze(
        sample: &Sample,
        context: &SampleContext,
    ) -> Result<(AnalysisResult, Option<Vec<Sample>>), AnalyzerError> {
        let _span = span!(Level::INFO, "ZipAnalyzer").entered();

        let sample_source = sample.get_fd()?;

        let mut dropped_samples: Vec<Sample> = Vec::new();

        match ZipArchive::new(sample_source) {
            Ok(mut archive) => {
                for fileid in 0..archive.len() {
                    let mut need_password = false;
                    match archive.by_index(fileid) {
                        Ok(mut file) => {
                            if file.is_dir() {
                                continue;
                            }

                            info!("Would unpack '{}'", file.name());
                            let mut file_data = Vec::new();
                            if file.read_to_end(&mut file_data).is_ok() {
                                dropped_samples.push(Sample {
                                    name: Some(file.name().to_string()),
                                    data: Location::InMem(file_data),
                                    unpacking_creds: None,
                                });
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
                            let mut successfully_decrypted = false;

                            for pw in unpacking_creds.as_slice() {
                                match archive.by_index_decrypt(fileid, pw.as_bytes()) {
                                    Ok(mut file) => {
                                        let mut file_data = Vec::new();
                                        if file.read_to_end(&mut file_data).is_ok() {
                                            info!(
                                                "Successfully decrypted '{}' with password '{}'",
                                                file.name(),
                                                pw
                                            );

                                            successfully_decrypted = true;

                                            dropped_samples.push(Sample {
                                                name: Some(file.name().to_string()),
                                                data: Location::InMem(file_data),
                                                unpacking_creds: None,
                                            });
                                            break;
                                        }
                                    }
                                    Err(ZipError::UnsupportedArchive(
                                        ZipError::PASSWORD_REQUIRED,
                                    ))
                                    | Err(ZipError::InvalidPassword) => (),
                                    Err(e) => {
                                        error!("Could not unpack sample: {:?}", e);
                                        break;
                                    }
                                }
                            }

                            if !successfully_decrypted {
                                warn!("Could not decrypt password-protected sample {:?}, no password matches", sample);
                            }
                        }
                    }
                }
            }
            Err(e) => {
                error!("Failed to open {:?} as a ZipArchive: {:?}", sample.name, e);

                let mut buf = Vec::new();

                if BzDecoder::new(sample.get_fd()?)
                    .read_to_end(&mut buf)
                    .is_ok()
                {
                    info!("Pushing bzip2 decrypted file on samples");
                    dropped_samples.push(Sample {
                        name: None,
                        data: Location::InMem(buf),
                        unpacking_creds: None,
                    })
                }
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
        &[
            "application/zip",
            "application/x-bzip",
            "application/x-bzip2",
        ]
    }
}

pub struct TarAnalyzer;

impl Analyze for TarAnalyzer {
    fn analyze(
        sample: &Sample,
        context: &SampleContext,
    ) -> Result<(AnalysisResult, Option<Vec<Sample>>), AnalyzerError> {
        let _span = span!(Level::INFO, "TarAnalyzer").entered();

        let sample_source = sample.get_fd()?;

        let mut dropped_samples: Vec<Sample> = Vec::new();

        let mut archive = tar::Archive::new(sample_source);
        match archive.entries() {
            Ok(entries) => {
                for entry in entries {
                    match entry {
                        Ok(mut entry) => {
                            let mut buf = Vec::new();
                            if entry.read_to_end(&mut buf).is_ok() {
                                let entry_name: Option<String> = {
                                    if let Ok(Some(p)) = entry.link_name() {
                                        p.to_str().map(String::from)
                                    } else {
                                        None
                                    }
                                };

                                dropped_samples.push(Sample {
                                    name: entry_name,
                                    data: Location::InMem(buf),
                                    unpacking_creds: None,
                                })
                            }
                        }
                        Err(e) => {
                            error!("Failed to read a entry of {:?}: {:?}", sample.name, e);
                        }
                    }
                }
            }
            Err(e) => {
                error!("Failed to open {:?} as a TarArchive: {:?}", sample.name, e);
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
        &["application/x-tar"]
    }
}

pub struct RawAnalyzer();

impl Analyze for RawAnalyzer {
    fn analyze(
        sample: &Sample,
        context: &SampleContext,
    ) -> Result<(AnalysisResult, Option<Vec<Sample>>), AnalyzerError> {
        let _span = span!(Level::INFO, "RawAnalyzer").entered();

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
        let _span = span!(Level::INFO, "MailAnalyzer").entered();

        let use_ml = env::var("USE_ML_FOR_CREDS_EXTRACTION").is_ok();

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

        let mut possible_passwords: Option<Arc<Vec<String>>> = None;
        let mut dropped_samples: Vec<Sample> = Vec::new();
        for (i, attachment) in mail.attachments().enumerate() {
            info!("attachment {}: {:?}", i, attachment.attachment_name());
            if possible_passwords.is_none() {
                possible_passwords = if let Some(body) = mail.body_text(0) {
                    if let Ok(cred_ex) = CredentialExtractor::new(use_ml) {
                        Some(Arc::new(cred_ex.get_creds(&body)?))
                    } else {
                        None
                    }
                } else {
                    None
                };
            }

            dropped_samples.push(Sample {
                name: attachment.attachment_name().map(|s| s.to_string()),
                data: Location::InMem(Vec::from(attachment.contents())),
                unpacking_creds: possible_passwords.clone(),
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
        let _span = span!(Level::INFO, "fetch_all_iso_files").entered();

        let mut dropped_samples: Vec<Sample> = Vec::new();

        let mut dir_stack: Vec<String> = Vec::new();
        dir_stack.push(String::from("/"));

        while let Some(cur_dir) = dir_stack.pop() {
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
                debug!("filename: {:?}", filename);
                match node_stat.type_ {
                    #[allow(non_upper_case_globals)]
                    iso9660_stat_s__STAT_DIR => {
                        let str_filename = filename.to_str().unwrap();
                        if str_filename != "." && str_filename != ".." {
                            debug!("'{}' is a directory", str_filename);
                            let mut fp_filename = cur_dir.clone();
                            fp_filename.push('/');
                            fp_filename.push_str(str_filename);

                            dir_stack.push(fp_filename);
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
        let _span = span!(Level::INFO, "read_sample_from_iso").entered();

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
        let _span = span!(Level::INFO, "Iso9660Analyzer").entered();

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

pub struct RarAnalyzer();

impl From<unrar::error::UnrarError> for AnalyzerError {
    fn from(value: unrar::error::UnrarError) -> Self {
        AnalyzerError::Other(Box::new(value))
    }
}

impl RarAnalyzer {
    fn need_password(file: &Path) -> Result<bool, UnrarError> {
        let mut ll = RarArchive::new(file).open_for_processing()?;

        while let Some(header) = ll.read_header()? {
            if header.entry().is_file() {
                match header.test() {
                    Err(e) if e.code == unrar::error::Code::MissingPassword => {
                        return Ok(true);
                    }
                    Err(e) => {
                        return Err(e);
                    }
                    Ok(f) => {
                        ll = f;
                    }
                }
            } else {
                ll = header.skip()?;
            }
        }
        Ok(false)
    }

    fn check_password(file: &Path, password: &str) -> Result<bool, UnrarError> {
        let mut ll = RarArchive::with_password(file, password).open_for_processing()?;

        while let Some(header) = ll.read_header()? {
            if header.entry().is_file() {
                match header.test() {
                    Err(e) if e.code == unrar::error::Code::BadPassword => {
                        return Ok(false);
                    }
                    Err(e) => {
                        return Err(e);
                    }
                    Ok(f) => {
                        ll = f;
                    }
                }
            } else {
                ll = header.skip()?;
            }
        }
        Ok(true)
    }

    fn extract_files(
        mut listing: OpenArchive<unrar::Process, unrar::CursorBeforeHeader>,
        sample: &Sample,
        context: &SampleContext,
    ) -> Result<Vec<Sample>, AnalyzerError> {
        let mut unpacked_files = Vec::new();
        env::set_current_dir(context.unpacking_location)?;
        while let Some(header) = listing.read_header()? {
            if header.entry().is_file() {
                let filename = header.entry().filename.clone();
                info!(
                    "[RarAnalyzer] Unpacking {:?} with size {}",
                    header.entry().filename,
                    header.entry().unpacked_size
                );
                listing = header.extract()?;
                let new_sample_name = {
                    let mut r = None;
                    if let Some(name) = filename.file_name() {
                        if let Some(s) = name.to_str() {
                            r = Some(s.to_string());
                        }
                    }
                    r
                };

                let mut dropped_loc = PathBuf::from(context.unpacking_location);
                dropped_loc.push(&filename);

                unpacked_files.push(Sample {
                    name: new_sample_name,
                    data: Location::File(dropped_loc),
                    unpacking_creds: sample.unpacking_creds.clone(),
                });
            } else {
                info!("[RarAnalyzer] skipping dir: {:?}", header.entry().filename);
                listing = header.skip()?;
            }
        }

        Ok(unpacked_files)
    }
}

impl Analyze for RarAnalyzer {
    fn mime_types() -> &'static [&'static str] {
        &[
            "application/vnd.rar",
            "application/x-rar-compressed",
            "application/x-rar",
        ]
    }

    fn analyze(
        sample: &Sample,
        context: &SampleContext,
    ) -> Result<(AnalysisResult, Option<Vec<Sample>>), AnalyzerError> {
        let sample_path: PathBuf = match &sample.data {
            Location::InMem(mem) => {
                let mut on_disk_path = PathBuf::from(context.unpacking_location);
                on_disk_path.push("archive.rar");
                fs::write(&on_disk_path, mem)?;
                on_disk_path
            }
            Location::File(path) => path.clone(),
        };

        let need_password =
            Self::need_password(&sample_path).context("Failed to check if password needed")?;

        if need_password && sample.unpacking_creds.is_none() {
            return Ok((
                AnalysisResult {
                    sample_id: None,
                    matched_yara_rules: None,
                },
                None,
            ));
        }

        let mut archive: Option<RarArchive> = None;

        if !need_password {
            archive = Some(RarArchive::new(sample_path.as_path()));
        } else if sample.unpacking_creds.is_some() {
            let creds = sample.unpacking_creds.as_ref().unwrap();
            for password in creds.as_slice() {
                if Self::check_password(&sample_path, password)
                    .context("Failed to check password")?
                {
                    info!(
                        "[RarAnalyzer] extracted {} with password \"{}\"",
                        sample_path.display(),
                        password
                    );
                    archive = Some(RarArchive::with_password(&sample_path, password));
                }
            }

            if archive.is_none() {
                info!(
                    "[RarAnalyzer] unable to find correct password for {}",
                    sample_path.display()
                );
            }
        };

        if archive.is_none() {
            return Ok((
                AnalysisResult {
                    sample_id: None,
                    matched_yara_rules: None,
                },
                None,
            ));
        }

        let archive = match archive.unwrap().open_for_processing() {
            Ok(a) => a,
            Err(e) => return Err(AnalyzerError::Other(e.into())),
        };

        let mut scanner = context.yara_rules.scanner()?;
        let found_rules: Vec<String> = scanner
            .scan_file(&sample_path)?
            .iter()
            .map(|r| r.identifier.to_string())
            .collect();

        let dropped_samples = Self::extract_files(archive, sample, context)?;

        Ok((
            AnalysisResult {
                sample_id: None,
                matched_yara_rules: if found_rules.is_empty() {
                    None
                } else {
                    Some(found_rules)
                },
            },
            if dropped_samples.is_empty() {
                None
            } else {
                Some(dropped_samples)
            },
        ))
    }
}
