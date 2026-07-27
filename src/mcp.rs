//! Raw JSON-RPC MCP server for cpp-guard.

use crate::Scanner;
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::sync::Mutex;

pub fn run_mcp_server() -> anyhow::Result<()> {
    let scanner = Mutex::new(Scanner::new()?);
    eprintln!("cpp-guard MCP server v0.1.0");

    let stdin = std::io::stdin();
    let reader = BufReader::new(stdin.lock());
    let stdout = std::io::stdout();

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() { continue; }

        let request: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                let err = json!({"jsonrpc":"2.0","error":{"code":-32700,"message":format!("Parse error: {e}")},"id":null});
                let mut out = stdout.lock();
                let _ = writeln!(out, "{}", serde_json::to_string(&err).unwrap_or_default());
                let _ = out.flush();
                continue;
            }
        };

        let id = request.get("id").cloned();
        let method = request.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let params = request.get("params").cloned();

        let response = match method {
            "initialize" => json!({"jsonrpc":"2.0","result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"cpp-guard","version":"0.1.0"}},"id":id}),
            "tools/list" => handle_tools_list(id),
            "tools/call" => handle_tool_call(id, params, &scanner),
            "notifications/initialized" => continue,
            _ => json!({"jsonrpc":"2.0","error":{"code":-32601,"message":format!("Method not found: {method}")},"id":id}),
        };

        let mut out = stdout.lock();
        let _ = writeln!(out, "{}", serde_json::to_string(&response).unwrap_or_default());
        let _ = out.flush();
    }
    Ok(())
}

fn handle_tools_list(id: Option<Value>) -> Value {
    json!({"jsonrpc":"2.0","result":{"tools":[
        {"name":"scan_project","description":"Scan a C++ project for safety issues.","inputSchema":{"type":"object","properties":{"project_path":{"type":"string","description":"Path to the C++ project root"}},"required":["project_path"]}},
        {"name":"list_checks","description":"List all available C++ safety checks.","inputSchema":{"type":"object","properties":{}}}
    ]},"id":id})
}

fn handle_tool_call(id: Option<Value>, params: Option<Value>, scanner: &Mutex<Scanner>) -> Value {
    let tool_name = params.as_ref().and_then(|p| p.get("name")).and_then(|n| n.as_str()).unwrap_or("");
    let args = params.as_ref().and_then(|p| p.get("arguments")).cloned().unwrap_or(Value::Null);

    match tool_name {
        "scan_project" => {
            let path_str = args.get("project_path").and_then(|v| v.as_str()).unwrap_or(".");
            let path = std::path::Path::new(path_str);
            let mut s = scanner.lock().unwrap();
            match s.scan(path) {
                Ok(report) => json!({"jsonrpc":"2.0","result":{"content":[{"type":"text","text":serde_json::to_string_pretty(&report).unwrap_or_default()}]},"id":id}),
                Err(e) => json!({"jsonrpc":"2.0","result":{"content":[{"type":"text","text":format!("Error: {e}")}]},"id":id}),
            }
        }
        "list_checks" => {
            let checks = json!({"checks":[
                {"id":"cpp-memory-leak","severity":"error","desc":"new without matching delete"},
                {"id":"cpp-null-deref","severity":"warning","desc":"pointer deref without null check"},
                {"id":"cpp-use-after-delete","severity":"warning","desc":"using pointer after delete without reset to nullptr"},
                {"id":"cpp-array-delete","severity":"error","desc":"new[] with scalar delete — UB"},
                {"id":"cpp-cstyle-cast","severity":"warning","desc":"C-style cast — type-unsafe"},
                {"id":"cpp-empty-catch","severity":"warning","desc":"empty catch block swallowing exceptions"},
                {"id":"cpp-destructor-throw","severity":"error","desc":"destructor contains throw — calls terminate()"},
                {"id":"cpp-format-string","severity":"error","desc":"printf with variable format string — format string vulnerability"},
                {"id":"cpp-path-traversal","severity":"warning","desc":"unsanitized path concatenation"},
                {"id":"cpp-sensitive-print","severity":"warning","desc":"sensitive data in print/debug output"},
                {"id":"cpp-sensitive-clear","severity":"warning","desc":"sensitive data freed without zeroing"},
                {"id":"cpp-delete-check","severity":"info","desc":"delete usage without nullptr assignment"}
            ]});
            json!({"jsonrpc":"2.0","result":{"content":[{"type":"text","text":serde_json::to_string_pretty(&checks).unwrap_or_default()}]},"id":id})
        }
        _ => json!({"jsonrpc":"2.0","error":{"code":-32602,"message":format!("Unknown tool: {tool_name}")},"id":id}),
    }
}
