use std::{env, path::PathBuf, process, sync::Arc};

use analyzer::AnalyzerError;

use crate::analyzer::Sample;

mod analyzer;
mod analyzers;
mod credential_extractor;
mod filelister;
mod inmem_file;
mod yara_ruleset;

fn main() -> Result<(), AnalyzerError> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        eprintln!(
            "Usage: {} [rules (.yara or directory containing .yara)] [file to scan]",
            args[0]
        );
        process::exit(1);
    }

    let _g = tracing_subscriber::fmt().with_line_number(true).init();

    let ana = analyzer::Analyzer::new(PathBuf::from(&args[1]).as_path())?;

    let sample = Sample {
        name: None,
        data: analyzer::Location::File(PathBuf::from(&args[2])),
        unpacking_creds: Some(Arc::new(vec!["test".to_string(), "geheim".to_string()])),
    };

    println!("Result: {:?}", ana.analyze(sample, None));

    Ok(())
}
