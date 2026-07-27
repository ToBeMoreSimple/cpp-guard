use clap::{Parser, Subcommand};
use colored::Colorize;
use cpp_guard::{report::Severity, Scanner};

#[derive(Parser)]
#[command(name = "cpp-guard", version, about = "Static analysis tool for C++ safety")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Scan {
        #[arg(default_value = ".")]
        path: String,
        #[arg(long)]
        json: bool,
    },
    Mcp,
    Checks,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Scan { path, json } => {
            let root = std::path::Path::new(&path).canonicalize()?;
            let mut scanner = Scanner::new()?;
            let report = scanner.scan(&root)?;

            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_report(&report);
            }
            if report.stats.errors > 0 {
                std::process::exit(1);
            }
        }
        Command::Mcp => {
            cpp_guard::mcp::run_mcp_server()?;
        }
        Command::Checks => {
            for c in CHECKS {
                let icon = match c.severity {
                    "error" => "✗".red(),
                    "warning" => "⚠".yellow(),
                    _ => "ℹ".dimmed(),
                };
                println!("  {icon} {:<25} {}", c.id.bold(), c.desc.dimmed());
            }
        }
    }
    Ok(())
}

struct Check { id: &'static str, severity: &'static str, desc: &'static str }
const CHECKS: &[Check] = &[
    Check { id: "cpp-memory-leak", severity: "error", desc: "new without matching delete" },
    Check { id: "cpp-null-deref", severity: "info", desc: "pointer deref — may be false positive for non-raw ptrs" },
    Check { id: "cpp-use-after-delete", severity: "warning", desc: "using pointer after delete" },
    Check { id: "cpp-array-delete", severity: "error", desc: "new[] with scalar delete" },
    Check { id: "cpp-cstyle-cast", severity: "warning", desc: "C-style cast — type-unsafe" },
    Check { id: "cpp-empty-catch", severity: "warning", desc: "empty catch swallows exceptions" },
    Check { id: "cpp-destructor-throw", severity: "error", desc: "destructor throw → terminate()" },
    Check { id: "cpp-format-string", severity: "error", desc: "printf with variable format string" },
    Check { id: "cpp-path-traversal", severity: "warning", desc: "unsanitized path concatenation" },
    Check { id: "cpp-sensitive-print", severity: "warning", desc: "sensitive data in logs" },
    Check { id: "cpp-sensitive-clear", severity: "warning", desc: "sensitive data freed without zeroing" },
    Check { id: "cpp-delete-check", severity: "info", desc: "delete without nullptr assignment" },
];

fn print_report(report: &cpp_guard::Report) {
    println!("\n{}", "══ cpp-guard audit report ══".bold().cyan());
    println!("  Project: {}\n", report.project.bold());

    if report.issues.is_empty() {
        println!("  {}\n", "✓ No issues found.".green());
        return;
    }

    for issue in &report.issues {
        let icon = match issue.severity {
            Severity::Error => "✗".red().bold(),
            Severity::Warning => "⚠".yellow().bold(),
            Severity::Info => "ℹ".blue().bold(),
        };
        println!("  {} {} {}:{} — {}",
            icon,
            format!("[{}]", issue.check).dimmed(),
            issue.file, issue.line.to_string().yellow(), issue.message,
        );
        if let Some(ref s) = issue.suggestion {
            println!("    {} {}", "→".dimmed(), s.dimmed());
        }
        println!();
    }

    let s = &report.stats;
    println!("{}", "── Summary ──".bold());
    println!("  Files: {}  Functions: {}  Classes: {}", s.files_scanned, s.functions, s.classes);
    println!("  {} errors  {} warnings  {} info  — {} total\n",
        s.errors.to_string().red().bold(),
        s.warnings.to_string().yellow().bold(),
        s.infos.to_string().blue().bold(),
        s.total_issues,
    );
}
