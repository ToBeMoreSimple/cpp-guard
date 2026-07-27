#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
    Info,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Issue {
    pub severity: Severity,
    pub check: &'static str,
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub message: String,
    pub suggestion: Option<String>,
}

#[derive(Debug, serde::Serialize)]
pub struct Report {
    pub project: String,
    pub issues: Vec<Issue>,
    pub stats: Stats,
}

#[derive(Debug, serde::Serialize)]
pub struct Stats {
    pub total_issues: usize,
    pub errors: usize,
    pub warnings: usize,
    pub infos: usize,
    pub functions: usize,
    pub classes: usize,
    pub files_scanned: usize,
}

impl Report {
    pub fn new(project: String) -> Self {
        Self {
            project,
            issues: Vec::new(),
            stats: Stats {
                total_issues: 0,
                errors: 0,
                warnings: 0,
                infos: 0,
                functions: 0,
                classes: 0,
                files_scanned: 0,
            },
        }
    }

    pub fn add(&mut self, issue: Issue) {
        match issue.severity {
            Severity::Error => self.stats.errors += 1,
            Severity::Warning => self.stats.warnings += 1,
            Severity::Info => self.stats.infos += 1,
        }
        self.stats.total_issues += 1;
        self.issues.push(issue);
    }
}
