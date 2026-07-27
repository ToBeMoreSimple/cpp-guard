use crate::report::{Issue, Severity};
use crate::scanner::FileInfo;

/// Destructors should never throw — it terminates the program.
pub fn check_destructor_throw(info: &FileInfo) -> Vec<Issue> {
    info.functions
        .iter()
        .filter(|f| f.is_destructor && info.throws.iter().any(|t| *t >= f.line))
        .map(|f| Issue {
            severity: Severity::Error,
            check: "cpp-destructor-throw",
            file: info.path.clone(),
            line: f.line,
            column: 1,
            message: format!(
                "destructor `{}` contains a `throw` — throwing from a destructor \
                 calls `std::terminate()` and crashes the program",
                f.name
            ),
            suggestion: Some(
                "Use `noexcept` on destructors (they are implicitly noexcept in C++11+). \
                 Catch and handle exceptions inside the destructor, never let them escape."
                    .to_string(),
            ),
        })
        .collect()
}
