use crate::report::{Issue, Severity};
use crate::scanner::FileInfo;

/// Logging or printing sensitive data (passwords, tokens, keys).
pub fn check_sensitive_print(info: &FileInfo) -> Vec<Issue> {
    info.prints
        .iter()
        .filter(|p| p.is_sensitive)
        .map(|p| Issue {
            severity: Severity::Warning,
            check: "cpp-sensitive-print",
            file: info.path.clone(),
            line: p.line,
            column: 1,
            message: format!(
                "sensitive data appears in print/debug output: `{}` \
                 — passwords, tokens, or keys should never be logged",
                p.text
            ),
            suggestion: Some(
                "Redact or remove sensitive data from log output. \
                 Use placeholder text like `***` or hash the value before logging."
                    .to_string(),
            ),
        })
        .collect()
}
