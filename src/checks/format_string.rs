use crate::report::{Issue, Severity};
use crate::scanner::FileInfo;

/// Detect printf-family functions called with user-controlled format strings.
pub fn check_format_string(info: &FileInfo) -> Vec<Issue> {
    let mut issues = Vec::new();
    let src = &info.source;

    for (i, line) in src.lines().enumerate() {
        let line_num = i + 1;
        let trimmed = line.trim();

        if trimmed.starts_with("//") || trimmed.is_empty() {
            continue;
        }

        // Match: printf(variable) without format string
        // or: sprintf(buf, variable) where format is a variable
        let is_printf = trimmed.contains("printf(") || trimmed.contains("fprintf(")
            || trimmed.contains("sprintf(") || trimmed.contains("snprintf(")
            || trimmed.contains("syslog(");

        if !is_printf {
            continue;
        }

        // Check if first argument is a variable (not a string literal)
        // Simple heuristic: find the first '(' and check what follows
        if let Some(args_start) = trimmed.find('(') {
            let args = &trimmed[args_start + 1..];
            let first_arg = args.split(',').next().unwrap_or("").trim();

            // Skip if first arg is a string literal with format specifiers
            if first_arg.starts_with('"') || first_arg.starts_with("L\"") {
                continue;
            }

            // Pure variable passed as format — dangerous
            if !first_arg.is_empty() && !first_arg.starts_with("std::")
                && first_arg != "this" && first_arg != "FILE*"
            {
                issues.push(Issue {
                    severity: Severity::Error,
                    check: "cpp-format-string",
                    file: info.path.clone(),
                    line: line_num,
                    column: 1,
                    message: format!(
                        "printf-style function called with variable `{}` as format string — \
                         format string vulnerability",
                        first_arg
                    ),
                    suggestion: Some(
                        "Always use a format string literal: `printf(\"%s\", var)` not `printf(var)`. \
                         For C++, use `std::cout` or `std::format` instead of printf-family functions."
                            .to_string(),
                    ),
                });
            }
        }
    }
    issues
}
