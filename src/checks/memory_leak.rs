use crate::report::{Issue, Severity};
use crate::scanner::FileInfo;

/// Detect allocations without matching deallocations in the same function.
pub fn check_memory_leak(info: &FileInfo) -> Vec<Issue> {
    let mut issues = Vec::new();

    for alloc in &info.allocations {
        let freed = info.deallocations.iter().any(|d| {
            d.var_name == alloc.var_name && d.func_name == alloc.func_name
        });

        if !freed {
            issues.push(Issue {
                severity: Severity::Error,
                check: "cpp-memory-leak",
                file: info.path.clone(),
                line: alloc.line,
                column: 1,
                message: format!(
                    "`{}` allocated with `new` but no matching `delete` found in `{}`",
                    alloc.var_name, alloc.func_name
                ),
                suggestion: Some(
                    "Add a corresponding `delete` (or `delete[]` for arrays) in all exit paths, \
                     or use `std::unique_ptr` / `std::shared_ptr` to manage ownership automatically."
                        .to_string(),
                ),
            });
        }
    }

    issues
}
