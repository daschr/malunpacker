use std::{env, path::PathBuf, process, sync::Arc};

use analyzer::AnalyzerError;
use log::info;

use crate::analyzer::Sample;

mod analyzer;
mod analyzers;
mod config;
mod credential_extractor;
mod filelister;
mod inmem_file;
mod yara_ruleset;

fn main() -> Result<(), AnalyzerError> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        eprintln!("Usage: {} [config file] [file to scan]", args[0]);
        process::exit(1);
    }

    let _g = tracing_subscriber::fmt().with_line_number(true).init();

    let conf = config::Config::read_from_file(PathBuf::from(&args[1]).as_path())?;

    info!("Parsed config.");

    let ana = analyzer::Analyzer::new(&conf.yara_rules, conf.yara_http_urls)?;

    info!("Created analyzer.");

    let sample = Sample {
        name: Some(args[2].clone()),
        data: analyzer::Location::File(PathBuf::from(&args[2])),
        unpacking_creds: Some(Arc::new(vec!["test".to_string(), "s3cr3t".to_string()])),
    };

    println!("Result: {:?}", ana.analyze(sample, None));

    Ok(())
}
