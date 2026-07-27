use crate::report::{Issue, Severity};
use crate::scanner::FileInfo;

/// `delete` on a pointer that may be null without prior check.
pub fn check_delete_no_null(info: &FileInfo) -> Vec<Issue> {
    info.deallocations
        .iter()
        .map(|d| Issue {
            severity: Severity::Info,
            check: "cpp-delete-check",
            file: info.path.clone(),
            line: d.line,
            column: 1,
            message: format!(
                "`delete` on `{}` — ensure this pointer is not used afterwards. \
                 Consider `ptr = nullptr;` after delete.",
                d.var_name
            ),
            suggestion: Some(
                "Deleting a null pointer is safe in C++, but using it afterwards is not. \
                 Set to `nullptr` after delete, or use smart pointers."
                    .to_string(),
            ),
        })
        .collect()
}
