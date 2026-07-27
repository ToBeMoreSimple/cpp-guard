use crate::report::{Issue, Severity};
use crate::scanner::FileInfo;

/// Detect path traversal: string concatenation that builds file paths
/// from user-controlled inputs or relative path components.
pub fn check_path_traversal(info: &FileInfo) -> Vec<Issue> {
    let mut issues = Vec::new();
    let src = &info.source;

    for (i, line) in src.lines().enumerate() {
        let line_num = i + 1;
        let trimmed = line.trim();

        // Skip comments and preprocessor
        if trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }

        // Pattern: string concatenation with ".." path component
        let has_dotdot = trimmed.contains("\"..\"") || trimmed.contains("\"../")
            || trimmed.contains("/..");

        // Pattern: path built with + operator and a variable
        let is_concat = trimmed.contains('+') && (trimmed.contains('"') || trimmed.contains("std::string"))
            || trimmed.contains("operator+") || trimmed.contains("std::filesystem::path");

        // Pattern: fopen/open with concatenated paths
        let has_file_open = trimmed.contains("fopen") || trimmed.contains("open(")
            || trimmed.contains("std::ofstream") || trimmed.contains("std::ifstream")
            || trimmed.contains("CreateFile");

        // Also check if ANY line in the file has a file open (for multi-line patterns)
        let file_has_open = src.lines().any(|l| {
            l.contains("fopen") || l.contains("open(") || l.contains("std::ofstream")
        });

        if has_dotdot || (is_concat && (has_file_open || file_has_open)) {
            issues.push(Issue {
                severity: Severity::Warning,
                check: "cpp-path-traversal",
                file: info.path.clone(),
                line: line_num,
                column: 1,
                message: format!(
                    "potential path traversal: `{}` — user input or relative paths in file operations",
                    trimmed
                ),
                suggestion: Some(
                    "Validate and sanitize file paths: canonicalize before use, reject '..' components, \
                     use `std::filesystem::canonical()` to resolve paths, whitelist allowed directories."
                        .to_string(),
                ),
            });
        }
    }
    issues
}
