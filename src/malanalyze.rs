use std::{env, path::PathBuf, process};

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

    let ana = analyzer::Analyzer::new(PathBuf::from(&args[1]).as_path())?;

    let sample = Sample {
        name: None,
        data: analyzer::Location::File(PathBuf::from(&args[2])),
        unpacking_creds: None,
    };

    println!("Result: {:?}", ana.analyze(sample, None));

    Ok(())
}
