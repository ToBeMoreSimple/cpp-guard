use crate::report::{Issue, Severity};
use crate::scanner::FileInfo;

/// Detect `new (std::nothrow)` allocations without subsequent nullptr check.
/// When `nothrow` new fails, it returns nullptr instead of throwing.
/// Using the pointer without checking is a null-deref bug.
pub fn check_nothrow_unchecked(info: &FileInfo) -> Vec<Issue> {
    let mut issues = Vec::new();

    for alloc in &info.allocations {
        if !alloc.is_nothrow {
            continue;
        }

        // Check if there's a null check right after this allocation
        let src = &info.source;
        let lines: Vec<&str> = src.lines().collect();
        let mut has_check = false;

        // Look at next 3 lines for null check
        for i in alloc.line..(alloc.line + 4).min(lines.len()) {
            if let Some(line) = lines.get(i) {
                let lt = line.to_lowercase();
                if lt.contains("nullptr") || lt.contains("null") || lt.contains("!ptr")
                    || lt.contains("== 0") || lt.contains("!= 0")
                {
                    has_check = true;
                    break;
                }
            }
        }

        if !has_check {
            issues.push(Issue {
                severity: Severity::Error,
                check: "cpp-nothrow-unchecked",
                file: info.path.clone(),
                line: alloc.line,
                column: 1,
                message: format!(
                    "`new (std::nothrow)` at line {} returns nullptr on failure, \
                     but no null check follows — immediate use will be UB",
                    alloc.line
                ),
                suggestion: Some(
                    "Add `if (!ptr) { return/throw/handle_error(); }` immediately after the allocation. \
                     Or remove `std::nothrow` and use exceptions for error handling."
                        .to_string(),
                ),
            });
        }
    }

    issues
}
