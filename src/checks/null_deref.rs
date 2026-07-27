use crate::report::{Issue, Severity};
use crate::scanner::FileInfo;

/// Pointer dereferences without a preceding null check.
pub fn check_null_deref(info: &FileInfo) -> Vec<Issue> {
    info.pointer_derefs
        .iter()
        .filter(|d| !d.has_null_check)
        .map(|d| Issue {
            severity: Severity::Warning,
            check: "cpp-null-deref",
            file: info.path.clone(),
            line: d.line,
            column: 1,
            message: format!("pointer `{}` dereferenced without null check", d.var_name),
            suggestion: Some(
                "Add `if (ptr != nullptr) { ... }` before dereferencing, or use a reference instead of a pointer."
                    .to_string(),
            ),
        })
        .collect()
}
