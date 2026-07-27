use crate::report::{Issue, Severity};
use crate::scanner::FileInfo;

/// Detect sensitive buffers (password, key, token) that are freed
/// without being securely zeroed first.
pub fn check_sensitive_clear(info: &FileInfo) -> Vec<Issue> {
    let mut issues = Vec::new();
    let src = &info.source;

    // Find variables named like password/key/token/secret
    let sensitive_vars: Vec<(usize, String)> = src.lines()
        .enumerate()
        .filter_map(|(i, line)| {
            let trimmed = line.trim();
            if trimmed.starts_with("//") || trimmed.is_empty() { return None; }

            let lower = trimmed.to_lowercase();
            if lower.contains("password") || lower.contains("secret")
                || lower.contains("token") || lower.contains("private_key")
                || lower.contains("api_key")
            {
                // Extract variable name
                for kw in &["password", "secret", "token", "private_key", "api_key"] {
                    if let Some(pos) = lower.find(kw) {
                        let var = &trimmed[pos..];
                        let name = var.split(|c: char| !c.is_alphanumeric() && c != '_')
                            .next().unwrap_or(var);
                        return Some((i + 1, name.to_string()));
                    }
                }
            }
            None
        })
        .collect();

    // Check if these vars have a corresponding memset/secure_zero before free/delete
    for (line_num, var_name) in &sensitive_vars {
        let mut has_clear = false;
        let mut has_delete = false;

        for (i, line) in src.lines().enumerate() {
            let ln = i + 1;
            if ln < *line_num { continue; }

            let lt = line.to_lowercase();
            if (lt.contains("delete") || lt.contains("free("))
                && lt.contains(&var_name.to_lowercase())
            {
                has_delete = true;
            }
            if (lt.contains("memset") || lt.contains("secure_zero")
                || lt.contains("explicit_bzero") || lt.contains("fill("))
                && lt.contains(&var_name.to_lowercase())
            {
                has_clear = true;
            }
        }

        if has_delete && !has_clear {
            issues.push(Issue {
                severity: Severity::Warning,
                check: "cpp-sensitive-clear",
                file: info.path.clone(),
                line: *line_num,
                column: 1,
                message: format!(
                    "sensitive variable `{}` is freed/deleted without being securely zeroed — \
                     residual data may remain in memory",
                    var_name
                ),
                suggestion: Some(
                    "Use `memset(ptr, 0, size)` or `std::fill(begin, end, 0)` before freeing. \
                     For C++11+, use `SecureZeroMemory` or `explicit_bzero`. \
                     Even better: use `std::vector<char>` with a custom allocator."
                        .to_string(),
                ),
            });
        }
    }

    issues
}
