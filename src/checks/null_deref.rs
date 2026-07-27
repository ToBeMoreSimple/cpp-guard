use crate::report::{Issue, Severity};
use crate::scanner::FileInfo;

/// Pointer dereferences without a preceding null check.
/// Only flags Warning when the pointer comes from a known allocation or FFI source.
pub fn check_null_deref(info: &FileInfo) -> Vec<Issue> {
    info.pointer_derefs
        .iter()
        .filter(|d| !d.has_null_check)
        .map(|d| {
            // Only Warning if the variable was allocated or is an extern parameter
            let is_allocated = info.allocations.iter().any(|a| a.var_name == d.var_name && a.func_name == d.func_name)
                || info.deallocations.iter().any(|a| a.var_name == d.var_name && a.func_name == d.func_name);
            let severity = if is_allocated { Severity::Warning } else { Severity::Info };

            Issue {
                severity,
                check: "cpp-null-deref",
                file: info.path.clone(),
                line: d.line,
                column: 1,
                message: format!("pointer `{}` dereferenced without null check", d.var_name),
                suggestion: if is_allocated {
                    Some("Add `if (ptr != nullptr) { ... }` before dereferencing.".to_string())
                } else {
                    Some("Verify this pointer is guaranteed non-null. This may be a false positive for smart pointers or references.".to_string())
                },
            }
        })
        .collect()
}
