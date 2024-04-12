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
    pub fn new() -> Self {
        Analyzer {}
    }

    pub fn analyze(&self, sample: Sample) -> Result<AnalResult, AnalError> {
        Ok(AnalysisResult {})
    }
}
