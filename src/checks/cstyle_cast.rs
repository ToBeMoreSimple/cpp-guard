use crate::report::{Issue, Severity};
use crate::scanner::FileInfo;

/// C-style casts like `(int*)ptr` — type-unsafe.
pub fn check_cstyle_cast(info: &FileInfo) -> Vec<Issue> {
    info.cstyle_casts
        .iter()
        .map(|c| Issue {
            severity: Severity::Warning,
            check: "cpp-cstyle-cast",
            file: info.path.clone(),
            line: c.line,
            column: 1,
            message: format!("C-style cast `{}` — type-unsafe, bypasses compiler checks", c.text),
            suggestion: Some(
                "Use `static_cast`, `dynamic_cast`, `const_cast`, or `reinterpret_cast` instead. \
                 C-style casts silently perform the most dangerous conversion without warning."
                    .to_string(),
            ),
        })
        .collect()
}
