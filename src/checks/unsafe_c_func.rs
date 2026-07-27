use crate::report::{Issue, Severity};
use crate::scanner::FileInfo;

/// Detect unsafe C standard library functions in C++ code.
/// In C++, safer alternatives exist (std::string, std::vector, smart pointers).
pub fn check_unsafe_c_func(info: &FileInfo) -> Vec<Issue> {
    let mut issues = Vec::new();
    let src = &info.source;

    // Unsafe C functions and their C++ alternatives
    let unsafe_funcs: &[(&str, &str)] = &[
        ("strcpy", "std::string::operator= or strcpy_s"),
        ("strcat", "std::string::operator+= or strcat_s"),
        ("sprintf", "std::ostringstream or snprintf"),
        ("gets", "std::cin or fgets"),
        ("scanf", "std::cin or fscanf_s"),
    ];

    // memcpy isn't inherently unsafe but often used unsafely
    let warn_funcs: &[(&str, &str)] = &[
        ("malloc", "new or std::make_unique"),
        ("realloc", "std::vector"),
        ("free", "delete or smart pointers"),
        ("memcpy", "std::copy or memcpy_s"),
        ("memset", "std::fill or memset_s"),
    ];

    for (i, line) in src.lines().enumerate() {
        let line_num = i + 1;
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with('#') {
            continue;
        }

        // Skip test files (often intentionally test C APIs)
        // But still flag for production code

        for (func, alternative) in unsafe_funcs {
            if trimmed.contains(func) && trimmed.contains("(") {
                issues.push(Issue {
                    severity: Severity::Warning,
                    check: "cpp-unsafe-c-func",
                    file: info.path.clone(),
                    line: line_num,
                    column: 1,
                    message: format!(
                        "unsafe C function `{}` used in C++ code — buffer overflow risk",
                        func
                    ),
                    suggestion: Some(format!(
                        "Use `{}` instead. C-style string functions are buffer-overflow prone \
                         and should be avoided in C++ code.",
                        alternative
                    )),
                });
            }
        }

        for (func, alternative) in warn_funcs {
            if trimmed.contains(func) && trimmed.contains("(") {
                // Only flag malloc/free/memcpy in non-test, non-wrapper code
                if *func == "malloc" || *func == "free" || *func == "realloc" {
                    let lower = trimmed.to_lowercase();
                    // Skip if already using safe variants like malloc_s
                    if lower.contains("_s(") { continue; }
                }
                issues.push(Issue {
                    severity: Severity::Info,
                    check: "cpp-unsafe-c-func",
                    file: info.path.clone(),
                    line: line_num,
                    column: 1,
                    message: format!(
                        "C-style `{}` used in C++ code — consider C++ alternative",
                        func
                    ),
                    suggestion: Some(format!(
                        "Consider using `{}` or the C++ standard library equivalent.",
                        alternative
                    )),
                });
            }
        }
    }

    issues
}
