//! MCP (Model Context Protocol) server over stdio.
//!
//! This is the agent-facing surface. By design it has **no tool that returns a
//! secret value**: agents work with paths, metadata and version numbers, and
//! ask the vault to generate or rotate. Even if a tool here were added by
//! mistake, the server refuses `reveal` for agent tokens.

use crate::{ApiError, Client};
use serde_json::{json, Value};
use std::io::{BufRead, Write};

const POLICY_SCHEMA: &str = r#"{"type":"object","description":"Generation policy. One of: {\"type\":\"password\",\"length\":32,\"symbols\":\"\"(optional, empty = none)} | {\"type\":\"hex\",\"bytes\":32} | {\"type\":\"base64url\",\"bytes\":32}"}"#;

fn tools() -> Value {
    let policy: Value = serde_json::from_str(POLICY_SCHEMA).unwrap_or(Value::Null);
    let path = json!({"type": "string", "description": "Secret path, lowercase segments, e.g. infra/pve/root"});
    json!([
        {
            "name": "vault_status",
            "description": "Check whether the vault is initialized and unsealed, and which identity/permissions this agent has.",
            "inputSchema": {"type": "object", "properties": {}}
        },
        {
            "name": "secret_list",
            "description": "List secrets this agent may see (path, kind, version, metadata). Never returns secret values.",
            "inputSchema": {"type": "object", "properties": {"prefix": {"type": "string", "description": "Optional path prefix, e.g. infra/"}}}
        },
        {
            "name": "secret_get",
            "description": "Get one secret's metadata and full version history (who changed it and when). Never returns the value.",
            "inputSchema": {"type": "object", "properties": {"path": path}, "required": ["path"]}
        },
        {
            "name": "secret_create",
            "description": "Create a secret. The vault generates the value internally and does not return it. Only pass `value` when a third party issued the credential and it is already known to you.",
            "inputSchema": {"type": "object", "properties": {
                "path": path,
                "kind": {"type": "string", "enum": ["password", "api_key", "ssh_key", "config", "note"]},
                "username": {"type": "string"},
                "url": {"type": "string"},
                "notes": {"type": "string"},
                "tags": {"type": "array", "items": {"type": "string"}},
                "policy": policy,
                "value": {"type": "string", "description": "Avoid. Externally issued value to store as-is."}
            }, "required": ["path"]}
        },
        {
            "name": "secret_update_metadata",
            "description": "Change a secret's username, url, notes or tags. Omitted fields are kept.",
            "inputSchema": {"type": "object", "properties": {
                "path": path,
                "username": {"type": "string"},
                "url": {"type": "string"},
                "notes": {"type": "string"},
                "tags": {"type": "array", "items": {"type": "string"}}
            }, "required": ["path"]}
        },
        {
            "name": "secret_generate",
            "description": "Generate a new version of a secret inside the vault without pushing it anywhere. The value is not returned. Use secret_rotate instead when the live system must change too.",
            "inputSchema": {"type": "object", "properties": {"path": path, "policy": policy}, "required": ["path"]}
        },
        {
            "name": "secret_rotate",
            "description": "Rotate a credential end to end: the vault generates a new value, applies it to the target system through the secret's configured driver, and makes it current only if that succeeds. On failure the previous value stays current. Returns the new version number, never the value.",
            "inputSchema": {"type": "object", "properties": {"path": path}, "required": ["path"]}
        },
        {
            "name": "secret_delete",
            "description": "Soft-delete a secret (an admin can still recover it).",
            "inputSchema": {"type": "object", "properties": {"path": path}, "required": ["path"]}
        }
    ])
}

fn arg<'a>(args: &'a Value, k: &str) -> Result<&'a str, ApiError> {
    args[k].as_str().ok_or_else(|| ApiError { status: 400, message: format!("missing string argument `{k}`") })
}

fn call(c: &Client, name: &str, args: &Value) -> Result<Value, ApiError> {
    match name {
        "vault_status" => {
            let mut st = c.get("/v1/sys/status")?;
            st["identity"] = c.get("/v1/whoami").unwrap_or_else(|e| json!({"error": e.message}));
            Ok(st)
        }
        "secret_list" => c.list(args["prefix"].as_str().unwrap_or("")),
        "secret_get" => c.get_secret(arg(args, "path")?),
        "secret_create" => {
            let mut body = json!({
                "path": arg(args, "path")?,
                "kind": args["kind"].as_str().unwrap_or("password"),
                "meta": {
                    "username": args["username"].as_str().unwrap_or(""),
                    "url": args["url"].as_str().unwrap_or(""),
                    "notes": args["notes"].as_str().unwrap_or(""),
                    "tags": args.get("tags").cloned().unwrap_or(json!([])),
                }
            });
            if let Some(p) = args.get("policy").filter(|p| !p.is_null()) {
                body["policy"] = p.clone();
            }
            if let Some(v) = args["value"].as_str() {
                body["value"] = json!(v);
            }
            c.post("/v1/secrets/create", &body)
        }
        "secret_update_metadata" => {
            let path = arg(args, "path")?;
            let mut meta = c.get_secret(path)?["meta"].clone();
            for k in ["username", "url", "notes", "tags"] {
                if let Some(v) = args.get(k).filter(|v| !v.is_null()) {
                    meta[k] = v.clone();
                }
            }
            c.post("/v1/secrets/update", &json!({"path": path, "meta": meta}))
        }
        "secret_generate" => {
            let mut body = json!({"path": arg(args, "path")?});
            if let Some(p) = args.get("policy").filter(|p| !p.is_null()) {
                body["policy"] = p.clone();
            }
            c.post("/v1/secrets/generate", &body)
        }
        "secret_rotate" => c.post("/v1/secrets/rotate", &json!({"path": arg(args, "path")?})),
        "secret_delete" => c.post("/v1/secrets/delete", &json!({"path": arg(args, "path")?})),
        _ => Err(ApiError { status: 404, message: format!("unknown tool `{name}`") }),
    }
}

fn handle(c: &Client, req: &Value) -> Option<Value> {
    let id = req.get("id").cloned();
    let method = req["method"].as_str().unwrap_or("");
    let result: Result<Value, (i64, String)> = match method {
        "initialize" => Ok(json!({
            "protocolVersion": req["params"]["protocolVersion"].as_str().unwrap_or("2025-06-18"),
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "jaword", "version": env!("CARGO_PKG_VERSION")},
            "instructions": "jaword is a secrets vault. You manage credentials by path and never see their values: create or generate them inside the vault, and use secret_rotate to change a live credential. Do not ask the user to paste secrets into chat."
        })),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({"tools": tools()})),
        "tools/call" => {
            let name = req["params"]["name"].as_str().unwrap_or("");
            let empty = json!({});
            let args = req["params"].get("arguments").unwrap_or(&empty);
            Ok(match call(c, name, args) {
                Ok(v) => json!({"content": [{"type": "text", "text": serde_json::to_string_pretty(&v).unwrap_or_default()}]}),
                Err(e) => json!({"content": [{"type": "text", "text": format!("error: {}", e.message)}], "isError": true}),
            })
        }
        m if m.starts_with("notifications/") => return None,
        _ => Err((-32601, format!("method not found: {method}"))),
    };
    // Requests without an id are notifications and get no reply.
    let id = id?;
    Some(match result {
        Ok(r) => json!({"jsonrpc": "2.0", "id": id, "result": r}),
        Err((code, message)) => json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}),
    })
}

pub fn serve(c: &Client) {
    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let reply = match serde_json::from_str::<Value>(&line) {
            Ok(req) => handle(c, &req),
            Err(_) => Some(json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": "parse error"}})),
        };
        if let Some(r) = reply {
            if writeln!(out, "{r}").and_then(|_| out.flush()).is_err() {
                break;
            }
        }
    }
}
