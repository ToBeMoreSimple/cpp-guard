use crate::report::{Issue, Severity};
use crate::scanner::FileInfo;

/// Detect `new T[n]` allocated with array form but deleted with scalar `delete`
/// instead of `delete[]`. This is undefined behavior.
pub fn check_array_delete(info: &FileInfo) -> Vec<Issue> {
    let mut issues = Vec::new();

    for alloc in &info.allocations {
        if !alloc.is_array {
            continue;
        }

        // Find matching deallocation
        if let Some(dealloc) = info.deallocations.iter()
            .find(|d| d.var_name == alloc.var_name && d.func_name == alloc.func_name)
        {
            if !dealloc.is_array {
                issues.push(Issue {
                    severity: Severity::Error,
                    check: "cpp-array-delete",
                    file: info.path.clone(),
                    line: dealloc.line,
                    column: 1,
                    message: format!(
                        "`{}` was allocated with `new[]` (line {}) but deleted with scalar `delete` — \
                         this is undefined behavior. Use `delete[]` for arrays.",
                        alloc.var_name, alloc.line
                    ),
                    suggestion: Some(
                        "Use `delete[] ptr;` for arrays allocated with `new[]`. \
                         Better: use `std::vector` instead of raw C arrays."
                            .to_string(),
                    ),
                });
            }
        }
    }

    issues
}
