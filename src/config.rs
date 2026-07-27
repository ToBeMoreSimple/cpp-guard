use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CppGuardConfig {
    #[serde(default)]
    pub disabled_checks: Vec<String>,
    #[serde(default)]
    pub severity_overrides: Vec<SeverityOverride>,
    #[serde(default = "default_max_unsafe_lines")]
    pub max_unsafe_lines: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SeverityOverride {
    pub check: String,
    pub severity: String,
}

fn default_max_unsafe_lines() -> usize {
    10
}

impl Default for CppGuardConfig {
    fn default() -> Self {
        Self {
            disabled_checks: vec![],
            severity_overrides: vec![],
            max_unsafe_lines: 10,
        }
    }
}

impl CppGuardConfig {
    pub fn load(project_root: &Path) -> Option<Self> {
        let config_path = project_root.join(".cppguard.toml");
        if !config_path.exists() {
            return None;
        }
        let content = std::fs::read_to_string(&config_path).ok()?;
        match toml::from_str(&content) {
            Ok(config) => {
                eprintln!("Loaded config: {}", config_path.display());
                Some(config)
            }
            Err(e) => {
                eprintln!("Warning: failed to parse {}: {}", config_path.display(), e);
                None
            }
        }
    }

    pub fn is_disabled(&self, check: &str) -> bool {
        self.disabled_checks.iter().any(|c| c == check)
    }

    /// Merge CLI --disable overrides into config
    pub fn with_disabled(mut self, disabled: &[String]) -> Self {
        for d in disabled {
            if !self.disabled_checks.contains(d) {
                self.disabled_checks.push(d.clone());
            }
        }
        self
    }
}
