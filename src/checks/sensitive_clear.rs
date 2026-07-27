use crate::report::{Issue, Severity};
use crate::scanner::FileInfo;

/// Detect sensitive buffers (password, key, token) that are freed
/// without being securely zeroed first.
/// Only flags when the variable is actively used with sensitive data input APIs.
pub fn check_sensitive_clear(info: &FileInfo) -> Vec<Issue> {
    let mut issues = Vec::new();
    let src = &info.source;

    // Sensitive input APIs
    let input_apis = [
        "getpass", "read_password", "GetPassword", "ReadPassword",
        "get_secret", "GetSecret", "ReadSecret", "decrypt",
        "Decrypt", "generate_key", "GenerateKey", "derive_key", "DeriveKey",
        "import_key", "ImportKey", "get_token", "GetToken",
    ];

    // Find variables that interact with sensitive APIs
    let sensitive_lines: Vec<usize> = src.lines()
        .enumerate()
        .filter_map(|(i, line)| {
            let lower = line.to_lowercase();
            for api in &input_apis {
                if lower.contains(&api.to_lowercase()) {
                    return Some(i + 1);
                }
            }
            None
        })
        .collect();

    if sensitive_lines.is_empty() {
        return issues;
    }

    // Find variables named like password/key/token/secret
    let var_patterns = ["password", "secret", "token", "key", "credential", "pin", "pwd"];

    for (i, line) in src.lines().enumerate() {
        let line_num = i + 1;
        let lower = line.to_lowercase();

        // Only check lines near sensitive API usage (within 20 lines)
        let near_sensitive = sensitive_lines.iter().any(|&sl| {
            (sl as isize - line_num as isize).abs() <= 20
        });
        if !near_sensitive { continue; }

        // Check if this line frees/deletes a sensitive variable
        let has_delete = lower.contains("delete") || lower.contains("free(");
        if !has_delete { continue; }

        // Check if variable name matches and no memset precedes
        for vp in &var_patterns {
            if lower.contains(vp) {
                // Check preceding lines for memset/secure_zero
                let mut has_clear = false;
                let start = if line_num > 5 { line_num - 5 } else { 0 };
                for l in src.lines().skip(start).take(10) {
                    let lt = l.to_lowercase();
                    if lt.contains("memset") || lt.contains("secure_zero")
                        || lt.contains("explicit_bzero") || lt.contains("fill(")
                    {
                        has_clear = true;
                        break;
                    }
                }

                if !has_clear {
                    issues.push(Issue {
                        severity: Severity::Warning,
                        check: "cpp-sensitive-clear",
                        file: info.path.clone(),
                        line: line_num,
                        column: 1,
                        message: format!(
                            "sensitive data freed at line {} without being securely zeroed — residual data may remain in memory",
                            line_num
                        ),
                        suggestion: Some(
                            "Use `memset(ptr, 0, size)` or `SecureZeroMemory` before freeing sensitive buffers."
                                .to_string(),
                        ),
                    });
                }
                break;
            }
        }
    }

    issues
}
