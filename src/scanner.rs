use crate::checks::{
    check_array_delete, check_cstyle_cast, check_delete_no_null, check_destructor_throw,
    check_empty_catch, check_format_string, check_memory_leak, check_nothrow_unchecked,
    check_null_deref, check_path_traversal, check_sensitive_clear, check_unsafe_c_func,
    check_use_after_delete,
};
use crate::report::{Issue, Report, Severity};
use anyhow::Result;
use std::path::Path;
use tree_sitter::Parser;

#[derive(Debug, Default)]
pub struct FileInfo {
    pub path: String,
    pub source: String,
    pub functions: Vec<FunctionInfo>,
    pub classes: Vec<ClassInfo>,
    pub allocations: Vec<AllocSite>,
    pub deallocations: Vec<DeallocSite>,
    pub pointer_derefs: Vec<PtrDeref>,
    pub null_checks: Vec<usize>, // line numbers
    pub cstyle_casts: Vec<PtrOp>,
    pub throws: Vec<usize>,
    pub catches: Vec<CatchInfo>,
    pub prints: Vec<PrintInfo>,
}

#[derive(Debug, Clone)]
pub struct FunctionInfo {
    pub name: String,
    pub line: usize,
    pub is_destructor: bool,
    pub is_inline: bool,
}

#[derive(Debug, Clone)]
pub struct ClassInfo {
    pub name: String,
    pub line: usize,
}

#[derive(Debug, Clone)]
pub struct AllocSite {
    pub line: usize,
    pub var_name: String,
    pub func_name: String,
    pub is_array: bool,
    pub is_nothrow: bool,
}

#[derive(Debug, Clone)]
pub struct DeallocSite {
    pub line: usize,
    pub var_name: String,
    pub func_name: String,
    pub is_array: bool,
}

#[derive(Debug, Clone)]
pub struct PtrDeref {
    pub line: usize,
    pub var_name: String,
    pub func_name: String,
    pub has_null_check: bool,
}

#[derive(Debug, Clone)]
pub struct PtrOp {
    pub line: usize,
    pub text: String,
}

#[derive(Debug, Clone)]
pub struct CatchInfo {
    pub line: usize,
    pub is_empty: bool,
}

#[derive(Debug, Clone)]
pub struct PrintInfo {
    pub line: usize,
    pub text: String,
    pub is_sensitive: bool,
}

pub struct Scanner {
    parser: Parser,
}

impl Scanner {
    pub fn new() -> Result<Self> {
        let mut parser = Parser::new();
        parser.set_language(&tree_sitter_cpp::LANGUAGE.into())?;
        Ok(Self { parser })
    }

    pub fn scan(&mut self, project_root: &Path) -> Result<Report> {
        let project_name = project_root
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let mut report = Report::new(project_name);
        let mut all_infos = Vec::new();

        for entry in walkdir::WalkDir::new(project_root)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| {
                let p = e.path();
                let ext = p.extension().and_then(|s| s.to_str()).unwrap_or("");
                matches!(ext, "cpp" | "cc" | "cxx" | "c++" | "C" | "hpp" | "hxx" | "h++" | "hh" | "h")
                    && !p.to_string_lossy().contains("/.git/")
            })
        {
            let source = match std::fs::read_to_string(entry.path()) {
                Ok(s) => s,
                Err(_) => continue,
            };

            let info = self.parse_file(entry.path().to_string_lossy().as_ref(), &source);
            let issues = self.check_file(&info);
            report.stats.files_scanned += 1;
            all_infos.push((info, issues));
        }

        for (info, issues) in all_infos {
            report.stats.functions += info.functions.len();
            report.stats.classes += info.classes.len();
            for issue in issues {
                report.add(issue);
            }
        }

        Ok(report)
    }

    pub fn parse_file(&mut self, path: &str, source: &str) -> FileInfo {
        let tree = self.parser.parse(source, None);
        let Some(tree) = tree else {
            return FileInfo {
                path: path.to_string(),
                source: source.to_string(),
                ..Default::default()
            };
        };

        let root = tree.root_node();
        let mut info = FileInfo {
            path: path.to_string(),
            source: source.to_string(),
            ..Default::default()
        };

        self.walk_node(root, "", &mut info);
        info
    }

    fn walk_node(&self, node: tree_sitter::Node, parent_func: &str, info: &mut FileInfo) {
        let kind = node.kind();
        let src = info.source.as_bytes();
        let line = node.start_position().row + 1;

        // Track current function context
        let func_name = if kind == "function_definition" {
            self.extract_function_name(node, src).unwrap_or_default()
        } else {
            parent_func.to_string()
        };

        match kind {
            "function_definition" => {
                let is_dtor = self.is_destructor(node, src);
                info.functions.push(FunctionInfo {
                    name: func_name.clone(),
                    line,
                    is_destructor: is_dtor,
                    is_inline: false,
                });

                // Check: destructor throwing
                if is_dtor && self.contains_throw(node, src) {
                    info.throws.push(line);
                }
            }

            "class_specifier" => {
                let name = node.child_by_field_name("name")
                    .map(|n| n.utf8_text(src).unwrap_or("").to_string())
                    .unwrap_or_default();
                info.classes.push(ClassInfo { name, line });
            }

            "new_expression" => {
                let var = self.find_var_in_assignment(node, src);
                let text = node.utf8_text(src).unwrap_or("");
                info.allocations.push(AllocSite {
                    line,
                    var_name: var,
                    func_name: func_name.clone(),
                    is_array: text.contains('['),
                    is_nothrow: text.contains("nothrow"),
                });
            }

            "delete_expression" => {
                let var = self.extract_delete_var(node, src);
                info.deallocations.push(DeallocSite {
                    line,
                    var_name: var.clone(),
                    func_name: func_name.clone(),
                    is_array: node.utf8_text(src).unwrap_or("").contains("[]"),
                });
                // Check: no null-assign after delete
                let after_text = self.text_after_node(node, src, 80);
                if !after_text.contains("nullptr") && !after_text.contains("NULL") && !after_text.contains('0') {
                    info.pointer_derefs.push(PtrDeref {
                        line,
                        var_name: var,
                        func_name: func_name.clone(),
                        has_null_check: false,
                    });
                }
            }

            "field_expression" | "pointer_expression" => {
                let text = node.utf8_text(src).unwrap_or("");
                if text.contains("->") || text.contains("(*") {
                    let var = text.split("->").next().unwrap_or(&text).to_string();
                    // Skip `this->` dereferences — always valid in member functions
                    if var.trim() == "this" || var.contains("this") {
                        // skip, don't flag
                    } else {
                        let has_null = info.null_checks.contains(&line)
                            || self.preceding_lines_have_null_check(line, &info.source);
                        info.pointer_derefs.push(PtrDeref {
                            line,
                            var_name: var,
                            func_name: func_name.clone(),
                            has_null_check: has_null,
                        });
                    }
                }
            }

            "if_statement" => {
                let text = node.utf8_text(src).unwrap_or("");
                if text.contains("nullptr") || text.contains("NULL") || text.contains(" == 0") {
                    info.null_checks.push(line);
                }
            }

            "cast_expression" | "binary_expression" => {
                let text = node.utf8_text(src).unwrap_or("");
                // C-style cast check
                if text.starts_with('(') && (text.contains("*)") || text.contains("int)")) {
                    info.cstyle_casts.push(PtrOp {
                        line,
                        text: text.to_string(),
                    });
                }
                // Print/output check
                let text_lower = text.to_lowercase();
                let should_check = if kind == "binary_expression" {
                    text_lower.contains("cout") || text_lower.contains("printf") || text_lower.contains("fprintf")
                } else {
                    text_lower.contains("cout") || text_lower.contains("printf") || text_lower.contains("std::cout")
                        || text_lower.contains("fprintf") || text_lower.contains("qDebug")
                };
                if should_check {
                    let sensitive = text_lower.contains("password") || text_lower.contains("secret")
                        || text_lower.contains("token") || text_lower.contains("key")
                        || text_lower.contains("private");
                    info.prints.push(PrintInfo {
                        line,
                        text: text.to_string(),
                        is_sensitive: sensitive,
                    });
                }
            }

            "throw_statement" => {
                info.throws.push(line);
            }

            "try_statement" | "catch_clause" => {
                if kind == "catch_clause" {
                    let body = node.child_by_field_name("body");
                    let is_empty = body.map_or(true, |b| {
                        let mut cursor = b.walk();
                        let mut only_trivial = true;
                        for c in b.named_children(&mut cursor) {
                            if !matches!(c.kind(), "{" | "}" | "comment") {
                                only_trivial = false;
                                break;
                            }
                        }
                        only_trivial
                    });
                    info.catches.push(CatchInfo { line, is_empty });
                }
            }

            "call_expression" => {
                let text = node.utf8_text(src).unwrap_or("").to_lowercase();
                if text.contains("cout") || text.contains("printf") || text.contains("std::cout")
                    || text.contains("fprintf") || text.contains("qDebug")
                {
                    let sensitive = text.contains("password") || text.contains("secret")
                        || text.contains("token") || text.contains("key")
                        || text.contains("private");
                    info.prints.push(PrintInfo {
                        line,
                        text: text.to_string(),
                        is_sensitive: sensitive,
                    });
                }
            }

            _ => {}
        }

        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            self.walk_node(child, &func_name, info);
        }
    }

    pub fn check_file(&self, info: &FileInfo) -> Vec<Issue> {
        let mut issues = Vec::new();

        // 1. Memory leak: alloc without dealloc
        issues.extend(check_memory_leak(info));

        // 2. Null pointer dereference
        issues.extend(check_null_deref(info));

        // 3. Use after delete (no nullptr assign)
        issues.extend(check_use_after_delete(info));

        // 4. C-style casts
        issues.extend(check_cstyle_cast(info));

        // 5. Empty catch blocks
        issues.extend(check_empty_catch(info));

        // 6. Destructor throws
        issues.extend(check_destructor_throw(info));

        // 7. Sensitive data in prints — deduplicate by line
        let mut seen_print_lines = std::collections::HashSet::new();
        for p in &info.prints {
            if p.is_sensitive && seen_print_lines.insert(p.line) {
                issues.push(Issue {
                    severity: Severity::Warning,
                    check: "cpp-sensitive-print",
                    file: info.path.clone(),
                    line: p.line,
                    column: 1,
                    message: format!(
                        "sensitive data appears in print/debug output: `{}` — passwords, tokens, or keys should never be logged",
                        p.text
                    ),
                    suggestion: Some(
                        "Redact or remove sensitive data from log output. Use placeholder text like `***` or hash the value before logging."
                            .to_string(),
                    ),
                });
            }
        }

        // 8. Delete without array form
        issues.extend(check_delete_no_null(info));

        // 9. Array new[] with scalar delete
        issues.extend(check_array_delete(info));

        // 10. Format string vulnerability
        issues.extend(check_format_string(info));

        // 11. Path traversal
        issues.extend(check_path_traversal(info));

        // 12. Sensitive data not cleared
        issues.extend(check_sensitive_clear(info));

        // 13. nothrow new without null check
        issues.extend(check_nothrow_unchecked(info));

        // 14. Unsafe C functions in C++ code
        issues.extend(check_unsafe_c_func(info));

        issues
    }

    fn extract_function_name(&self, node: tree_sitter::Node, src: &[u8]) -> Option<String> {
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if child.kind() == "function_declarator" {
                let mut c2 = child.walk();
                for decl_child in child.named_children(&mut c2) {
                    if decl_child.kind() == "identifier"
                        || decl_child.kind() == "field_identifier"
                        || decl_child.kind() == "destructor_name"
                    {
                        return Some(decl_child.utf8_text(src).unwrap_or("").to_string());
                    }
                }
            }
        }
        None
    }

    fn is_destructor(&self, node: tree_sitter::Node, src: &[u8]) -> bool {
        let text = node.utf8_text(src).unwrap_or("");
        text.contains('~')
    }

    fn contains_throw(&self, node: tree_sitter::Node, src: &[u8]) -> bool {
        node.utf8_text(src).unwrap_or("").contains("throw")
    }

    fn find_var_in_assignment(&self, node: tree_sitter::Node, src: &[u8]) -> String {
        // Recursively find the first identifier in a subtree
        fn find_ident(node: tree_sitter::Node, src: &[u8]) -> Option<String> {
            if node.kind() == "identifier" || node.kind() == "field_identifier" {
                return Some(node.utf8_text(src).unwrap_or("").to_string());
            }
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if let Some(name) = find_ident(child, src) {
                    return Some(name);
                }
            }
            None
        }

        let mut parent = node.parent();
        while let Some(p) = parent {
            if matches!(p.kind(), "assignment_expression" | "init_declarator" | "declaration") {
                if let Some(name) = find_ident(p, src) {
                    return name;
                }
            }
            parent = p.parent();
        }
        String::new()
    }

    fn extract_delete_var(&self, node: tree_sitter::Node, src: &[u8]) -> String {
        let text = node.utf8_text(src).unwrap_or("");
        text.trim_start_matches("delete")
            .trim_start_matches("[] ")
            .trim()
            .trim_end_matches(';')
            .to_string()
    }

    fn text_after_node(&self, node: tree_sitter::Node, src: &[u8], len: usize) -> String {
        let end = node.end_byte();
        let limit = src.len().min(end + len);
        String::from_utf8_lossy(&src[end..limit]).to_string()
    }

    fn preceding_lines_have_null_check(&self, line: usize, source: &str) -> bool {
        let lines: Vec<&str> = source.lines().collect();
        let start = if line > 5 { line - 5 } else { 0 };
        for i in start..line.saturating_sub(1) {
            if let Some(l) = lines.get(i) {
                let lt = l.to_lowercase();
                if lt.contains("nullptr") || lt.contains("null") || lt.contains("== 0") {
                    return true;
                }
            }
        }
        false
    }
}
