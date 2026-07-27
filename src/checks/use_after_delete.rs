use crate::report::{Issue, Severity};
use crate::scanner::FileInfo;

/// `delete` without setting pointer to nullptr — use-after-free risk.
pub fn check_use_after_delete(info: &FileInfo) -> Vec<Issue> {
    info.deallocations
        .iter()
        .filter(|d| {
            // Check if there's a subsequent use without nullptr assignment
            info.pointer_derefs.iter().any(|u| {
                u.var_name == d.var_name && u.line > d.line && u.func_name == d.func_name
            })
        })
        .map(|d| Issue {
            severity: Severity::Warning,
            check: "cpp-use-after-delete",
            file: info.path.clone(),
            line: d.line,
            column: 1,
            message: format!(
                "`{}` deleted at line {} but used again later without being set to nullptr",
                d.var_name, d.line
            ),
            suggestion: Some(
                "Set pointer to `nullptr` after `delete`: `delete ptr; ptr = nullptr;`. \
                 Even better, use `std::unique_ptr` or `std::shared_ptr`."
                    .to_string(),
            ),
        })
        .collect()
}
