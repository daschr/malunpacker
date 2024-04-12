use std::path::PathBuf;

pub enum Sample {
    Mail(Vec<u8>),
    Raw(Vec<u8>),
}

pub enum AnalysisError {
    NotValid,
}

pub struct AnalysisResult {}

pub struct Analyzer {}

impl Analyzer {
    pub fn new(yara_rules: &PathBuf) -> Self {
        Analyzer {}
    }

    pub fn analyze(&self, sample: Sample) -> Result<AnalResult, AnalError> {
        Ok(AnalysisResult {})
    }
}
