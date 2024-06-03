use std::{
    path::Path,
    sync::{atomic::AtomicUsize, RwLock},
};

use yara::{Compiler, Rules as YaraRules};

use crate::analyzer::AnalyzerError;

pub struct YaraRuleset {
    pos: AtomicUsize,
    yara_rules_db: [RwLock<Option<YaraRules>>; 2],
}

impl YaraRuleset {
    pub fn new() -> Self {
        YaraRuleset {
            pos: AtomicUsize::new(0),
            yara_rules_db: [RwLock::new(None), RwLock::new(None)],
        }
    }

    pub fn update_yara_rules(&self, yara_rules_loc: &Path) -> Result<(), AnalyzerError> {
        let mut compiler: Compiler = Compiler::new()?;

        if yara_rules_loc.is_file() {
            compiler = compiler.add_rules_file(yara_rules_loc)?;
        } else {
            for p in std::fs::read_dir(yara_rules_loc)? {
                let p = p?.path();
                if p.is_file() && matches!(p.extension().map(|s| s.to_str()), Some(Some("yar"))) {
                    compiler = compiler.add_rules_file(p)?;
                }
            }
        }

        let yara_rules = compiler.compile_rules()?;

        let new_pos = self.pos.load(std::sync::atomic::Ordering::Acquire) ^ 1;

        let mut d = self.yara_rules_db[new_pos]
            .write()
            .expect("Failed to get lock");

        *d = Some(yara_rules);

        self.pos
            .store(new_pos, std::sync::atomic::Ordering::Release);
        Ok(())
    }

    pub fn get_current_rules(&self) -> std::sync::RwLockReadGuard<'_, Option<YaraRules>> {
        let pos = self.pos.load(std::sync::atomic::Ordering::Acquire);

        self.yara_rules_db[pos].read().unwrap()
    }
}
