use crate::report::{Issue, Severity};
use crate::scanner::FileInfo;

/// Empty catch blocks silently swallow exceptions.
pub fn check_empty_catch(info: &FileInfo) -> Vec<Issue> {
    info.catches
        .iter()
        .filter(|c| c.is_empty)
        .map(|c| Issue {
            severity: Severity::Warning,
            check: "cpp-empty-catch",
            file: info.path.clone(),
            line: c.line,
            column: 1,
            message: "empty `catch(...)` block — silently swallows all exceptions".to_string(),
            suggestion: Some(
                "At minimum, log the exception. Never silently swallow exceptions. \
                 Use `catch (const std::exception& e) { log(e.what()); }` \
                 or re-throw if you can't handle it."
                    .to_string(),
            ),
        })
        .collect()
}
