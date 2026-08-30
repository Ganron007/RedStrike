from __future__ import annotations

import argparse
import ipaddress
import os
from typing import Any
from urllib.parse import urlparse

import requests


def cadre_remote_paths() -> dict[str, str]:
    """Linux paths for the API host. CADRE_ROOT need not exist on the MCP client."""
    root = os.environ.get("CADRE_ROOT", "").strip().rstrip("/").rstrip("\\")
    if not root:
        return {}
    auto = f"{root}/attack-matrix"
    return {
        "graph": f"{auto}/Campaign/automation/campaign-graph.yaml",
        "seed": f"{auto}/Campaign/automation/lab-seed-creds.json",
        "automation_root": f"{auto}/04-automation/linux",
    }


def _is_local_host(host: str | None) -> bool:
    if not host:
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _validate_api_url(api_url: str) -> None:
    parsed = urlparse(api_url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("API URL must be an absolute URL")

    if parsed.scheme == "http" and not _is_local_host(parsed.hostname):
        raise ValueError("Refusing non-local HTTP API URL; use HTTPS for remote API endpoints")


def _post(
    api_url: str,
    path: str,
    payload: dict[str, Any],
    *,
    timeout: int = 300,
) -> dict[str, Any]:
    _validate_api_url(api_url)
    response = requests.post(f"{api_url.rstrip('/')}{path}", json=payload, timeout=timeout)
    response.raise_for_status()
    return response.json()


def build_payload(
    target: str,
    domain: str = "",
    username: str = "",
    password: str = "",
    nt_hash: str = "",
    mode: str = "observe",
    kdc_host: str = "",
    engagement_id: str = "",
    operator_id: str = "",
    run_id: str = "",
    source_system: str = "",
    evidence_tags: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "target": target,
        "domain": domain or None,
        "username": username or None,
        "password": password or None,
        "nt_hash": nt_hash or None,
        "mode": mode,
        "kdc_host": kdc_host or None,
        "engagement_id": engagement_id or None,
        "operator_id": operator_id or None,
        "run_id": run_id or None,
        "source_system": source_system or None,
        "evidence_tags": evidence_tags or [],
    }


def create_mcp(api_url: str):
    _validate_api_url(api_url)

    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        from fastmcp import FastMCP

    mcp = FastMCP("redstrike")

    @mcp.tool()
    def enumerate_domain_users(
        target: str,
        domain: str = "",
        username: str = "",
        password: str = "",
        nt_hash: str = "",
        mode: str = "observe",
        kdc_host: str = "",
        engagement_id: str = "",
        operator_id: str = "",
        run_id: str = "",
        source_system: str = "",
        evidence_tags: list[str] | None = None,
    ) -> dict[str, Any]:
        """Enumerate AD domain users through a scoped, read-only NetExec LDAP operation."""
        return _post(
            api_url,
            "/ad/users",
            build_payload(
                target,
                domain,
                username,
                password,
                nt_hash,
                mode,
                kdc_host,
                engagement_id,
                operator_id,
                run_id,
                source_system,
                evidence_tags,
            ),
        )

    @mcp.tool()
    def enumerate_domain_groups(
        target: str,
        domain: str = "",
        username: str = "",
        password: str = "",
        nt_hash: str = "",
        mode: str = "observe",
        kdc_host: str = "",
        engagement_id: str = "",
        operator_id: str = "",
        run_id: str = "",
        source_system: str = "",
        evidence_tags: list[str] | None = None,
    ) -> dict[str, Any]:
        """Enumerate AD domain groups through a scoped, read-only NetExec LDAP operation."""
        return _post(
            api_url,
            "/ad/groups",
            build_payload(
                target,
                domain,
                username,
                password,
                nt_hash,
                mode,
                kdc_host,
                engagement_id,
                operator_id,
                run_id,
                source_system,
                evidence_tags,
            ),
        )

    @mcp.tool()
    def enumerate_domain_computers(
        target: str,
        domain: str = "",
        username: str = "",
        password: str = "",
        nt_hash: str = "",
        mode: str = "observe",
        kdc_host: str = "",
        engagement_id: str = "",
        operator_id: str = "",
        run_id: str = "",
        source_system: str = "",
        evidence_tags: list[str] | None = None,
    ) -> dict[str, Any]:
        """Enumerate AD computer accounts."""
        return _post(
            api_url,
            "/ad/computers",
            build_payload(
                target,
                domain,
                username,
                password,
                nt_hash,
                mode,
                kdc_host,
                engagement_id,
                operator_id,
                run_id,
                source_system,
                evidence_tags,
            ),
        )

    @mcp.tool()
    def enumerate_password_policy(
        target: str,
        domain: str = "",
        username: str = "",
        password: str = "",
        nt_hash: str = "",
        mode: str = "observe",
        kdc_host: str = "",
        engagement_id: str = "",
        operator_id: str = "",
        run_id: str = "",
        source_system: str = "",
        evidence_tags: list[str] | None = None,
    ) -> dict[str, Any]:
        """Read the domain password and lockout policy."""
        return _post(
            api_url,
            "/ad/password-policy",
            build_payload(
                target,
                domain,
                username,
                password,
                nt_hash,
                mode,
                kdc_host,
                engagement_id,
                operator_id,
                run_id,
                source_system,
                evidence_tags,
            ),
        )

    @mcp.tool()
    def enumerate_shares(
        target: str,
        domain: str = "",
        username: str = "",
        password: str = "",
        nt_hash: str = "",
        mode: str = "observe",
        kdc_host: str = "",
        engagement_id: str = "",
        operator_id: str = "",
        run_id: str = "",
        source_system: str = "",
        evidence_tags: list[str] | None = None,
    ) -> dict[str, Any]:
        """Enumerate SMB shares and access levels."""
        return _post(
            api_url,
            "/ad/shares",
            build_payload(
                target,
                domain,
                username,
                password,
                nt_hash,
                mode,
                kdc_host,
                engagement_id,
                operator_id,
                run_id,
                source_system,
                evidence_tags,
            ),
        )

    @mcp.tool()
    def find_asrep_roastable_accounts(
        target: str,
        domain: str = "",
        username: str = "",
        password: str = "",
        nt_hash: str = "",
        mode: str = "assess",
        kdc_host: str = "",
        engagement_id: str = "",
        operator_id: str = "",
        run_id: str = "",
        source_system: str = "",
        evidence_tags: list[str] | None = None,
    ) -> dict[str, Any]:
        """Collect AS-REP roastable account evidence in authorized scope."""
        return _post(
            api_url,
            "/ad/asrep-roastable",
            build_payload(
                target,
                domain,
                username,
                password,
                nt_hash,
                mode,
                kdc_host,
                engagement_id,
                operator_id,
                run_id,
                source_system,
                evidence_tags,
            ),
        )

    @mcp.tool()
    def find_kerberoastable_accounts(
        target: str,
        domain: str = "",
        username: str = "",
        password: str = "",
        nt_hash: str = "",
        mode: str = "assess",
        kdc_host: str = "",
        engagement_id: str = "",
        operator_id: str = "",
        run_id: str = "",
        source_system: str = "",
        evidence_tags: list[str] | None = None,
    ) -> dict[str, Any]:
        """Collect Kerberoastable account evidence in authorized scope."""
        return _post(
            api_url,
            "/ad/kerberoastable",
            build_payload(
                target,
                domain,
                username,
                password,
                nt_hash,
                mode,
                kdc_host,
                engagement_id,
                operator_id,
                run_id,
                source_system,
                evidence_tags,
            ),
        )

    @mcp.tool()
    def find_delegation_paths(
        target: str,
        domain: str = "",
        username: str = "",
        password: str = "",
        nt_hash: str = "",
        mode: str = "assess",
        kdc_host: str = "",
        engagement_id: str = "",
        operator_id: str = "",
        run_id: str = "",
        source_system: str = "",
        evidence_tags: list[str] | None = None,
    ) -> dict[str, Any]:
        """Find AD Kerberos delegation relationships."""
        return _post(
            api_url,
            "/ad/delegation",
            build_payload(
                target,
                domain,
                username,
                password,
                nt_hash,
                mode,
                kdc_host,
                engagement_id,
                operator_id,
                run_id,
                source_system,
                evidence_tags,
            ),
        )

    @mcp.tool()
    def find_admin_count_accounts(
        target: str,
        domain: str = "",
        username: str = "",
        password: str = "",
        nt_hash: str = "",
        mode: str = "assess",
        kdc_host: str = "",
        engagement_id: str = "",
        operator_id: str = "",
        run_id: str = "",
        source_system: str = "",
        evidence_tags: list[str] | None = None,
    ) -> dict[str, Any]:
        """Find accounts marked with adminCount for privileged account review."""
        return _post(
            api_url,
            "/ad/admin-count",
            build_payload(
                target,
                domain,
                username,
                password,
                nt_hash,
                mode,
                kdc_host,
                engagement_id,
                operator_id,
                run_id,
                source_system,
                evidence_tags,
            ),
        )

    @mcp.tool()
    def enumerate_adcs(
        target: str,
        domain: str = "",
        username: str = "",
        password: str = "",
        nt_hash: str = "",
        mode: str = "assess",
        kdc_host: str = "",
        engagement_id: str = "",
        operator_id: str = "",
        run_id: str = "",
        source_system: str = "",
        evidence_tags: list[str] | None = None,
    ) -> dict[str, Any]:
        """Enumerate Active Directory Certificate Services objects in authorized scope."""
        return _post(
            api_url,
            "/ad/adcs",
            build_payload(
                target,
                domain,
                username,
                password,
                nt_hash,
                mode,
                kdc_host,
                engagement_id,
                operator_id,
                run_id,
                source_system,
                evidence_tags,
            ),
        )

    @mcp.tool()
    def campaign_start(
        engagement_id: str,
        beachhead: str = "windows",
        operator: str = "",
        allow_mbr01_stage: bool = False,
        graph: str = "",
        automation_root: str = "",
        seed: str = "",
        branches: str = "all",
        profile: str = "",
    ) -> dict[str, Any]:
        """Start a campaign engagement (seed ledger, set beachhead/operator/branches/profile)."""
        paths = cadre_remote_paths()
        return _post(
            api_url,
            "/campaign/start",
            {
                "engagement_id": engagement_id,
                "beachhead": beachhead,
                "operator": operator or ("provisioning" if paths else None),
                "allow_mbr01_stage": allow_mbr01_stage,
                "graph": graph or paths.get("graph"),
                "automation_root": automation_root or paths.get("automation_root"),
                "seed": seed or paths.get("seed"),
                "branches": branches,
                "profile": profile or ("autonomous" if paths else None),
            },
        )

    @mcp.tool()
    def campaign_approve(
        engagement_id: str,
        gate: str,
        note: str = "",
        beachhead: str = "windows",
        allow_mbr01_stage: bool = False,
    ) -> dict[str, Any]:
        """Approve a HITL gate (dcsync|ticket|forest|persistence|acl_write|site_takeover)."""
        return _post(
            api_url,
            "/campaign/approve",
            {
                "engagement_id": engagement_id,
                "gate": gate,
                "note": note or None,
                "beachhead": beachhead,
                "allow_mbr01_stage": allow_mbr01_stage,
            },
        )

    @mcp.tool()
    def campaign_run_phase(
        engagement_id: str,
        beachhead: str = "windows",
        operator: str = "",
        phase: str = "0-10",
        dry_run: bool | None = None,
        stop_on_hitl: bool | None = None,
        allow_mbr01_stage: bool = False,
        graph: str = "",
        automation_root: str = "",
        seed: str = "",
        branches: str = "all",
        profile: str = "",
        nodes: str = "",
        prefer_script: bool = False,
    ) -> dict[str, Any]:
        """Run phases/branches. Omit dry_run on an ungated API to execute. CADRE fills Linux graph/seed paths."""
        paths = cadre_remote_paths()
        return _post(
            api_url,
            "/campaign/run_phase",
            {
                "engagement_id": engagement_id,
                "beachhead": beachhead,
                "operator": operator or ("provisioning" if paths else None),
                "phase": phase,
                "dry_run": dry_run,
                "stop_on_hitl": stop_on_hitl,
                "allow_mbr01_stage": allow_mbr01_stage,
                "graph": graph or paths.get("graph"),
                "automation_root": automation_root or paths.get("automation_root"),
                "seed": seed or paths.get("seed"),
                "branches": branches,
                "profile": profile or ("autonomous" if paths else None),
                "nodes": nodes or None,
                "prefer_script": prefer_script or bool(paths),
            },
            timeout=7200,
        )

    @mcp.tool()
    def campaign_status(
        engagement_id: str,
        beachhead: str = "windows",
    ) -> dict[str, Any]:
        """Return engagement HITL state, ledger creds, and graph identity."""
        return _post(
            api_url,
            "/campaign/status",
            {
                "engagement_id": engagement_id,
                "beachhead": beachhead,
            },
        )

    @mcp.tool()
    def campaign_stream(
        engagement_id: str,
        stream: str,
        beachhead: str = "linux",
        dry_run: bool | None = None,
        graph: str = "",
        automation_root: str = "",
        seed: str = "",
        profile: str = "",
    ) -> dict[str, Any]:
        """Run Campaign E (phase 9) or F (phase 10) thin stream — no ws01 routing."""
        paths = cadre_remote_paths()
        return _post(
            api_url,
            "/campaign/stream",
            {
                "engagement_id": engagement_id,
                "stream": stream,
                "beachhead": beachhead,
                "dry_run": dry_run,
                "graph": graph or paths.get("graph"),
                "automation_root": automation_root or paths.get("automation_root"),
                "seed": seed or paths.get("seed"),
                "profile": profile or ("autonomous" if paths else None),
            },
            timeout=7200,
        )

    @mcp.tool()
    def build_intent(
        intent: str,
        args: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Preview typed builder argv for an intent (secrets redacted). LLM must not invent argv."""
        return _post(
            api_url,
            "/builders/preview",
            {"intent": intent, "args": args or {}},
        )

    @mcp.tool()
    def execute_intent(
        intent: str,
        args: dict[str, Any] | None = None,
        mode: str = "validate",
    ) -> dict[str, Any]:
        """Execute a typed builder intent. Requires ungated/high-risk API plus in-scope host and domain."""
        return _post(
            api_url,
            "/builders/execute",
            {"intent": intent, "args": args or {}, "mode": mode},
        )

    @mcp.tool()
    def bloodhound_query(
        cypher_query: str,
        limit: int = 50,
    ) -> dict[str, Any]:
        """Execute a BloodHound OpenCypher graph query to find attack paths to High Value Targets."""
        return _post(
            api_url,
            "/bloodhound/query",
            {"query": cypher_query, "limit": limit},
        )

    @mcp.tool()
    def recommend_next_steps(
        engagement_id: str,
        objective: str = "Domain Admins",
    ) -> dict[str, Any]:
        """Analyze current CredentialLedger and discovered entities to recommend top 3 ranked next-best-action intents."""
        return _post(
            api_url,
            "/campaign/recommend",
            {"engagement_id": engagement_id, "objective": objective},
        )

    @mcp.tool()
    def c2_list_sessions(
        backend: str = "sliver",
        endpoint: str = "",
    ) -> dict[str, Any]:
        """List active C2 sessions/beacons from the C2 teamserver (Sliver or Meridian)."""
        return _post(
            api_url,
            "/c2/sessions",
            {"backend": backend, "endpoint": endpoint or None},
        )

    @mcp.tool()
    def c2_execute_assembly(
        session_id: str,
        assembly: str,
        args: list[str] | None = None,
        backend: str = "sliver",
        endpoint: str = "",
        timeout_seconds: int = 120,
    ) -> dict[str, Any]:
        """Execute a .NET assembly in-memory inside the remote C2 implant session."""
        return _post(
            api_url,
            "/c2/execute-assembly",
            {
                "session_id": session_id,
                "assembly": assembly,
                "args": args or [],
                "backend": backend,
                "endpoint": endpoint or None,
                "timeout_seconds": timeout_seconds,
            },
            timeout=timeout_seconds + 30,
        )

    @mcp.tool()
    def c2_shell(
        session_id: str,
        command: str,
        backend: str = "sliver",
        endpoint: str = "",
        timeout_seconds: int = 60,
    ) -> dict[str, Any]:
        """Execute a remote shell command inside the C2 implant session context."""
        return _post(
            api_url,
            "/c2/shell",
            {
                "session_id": session_id,
                "command": command,
                "backend": backend,
                "endpoint": endpoint or None,
                "timeout_seconds": timeout_seconds,
            },
            timeout=timeout_seconds + 30,
        )

    @mcp.tool()
    def c2_psexec(
        session_id: str,
        target: str,
        service_name: str = "RedStrikeSvc",
        bin_path: str = "",
        backend: str = "sliver",
        endpoint: str = "",
        timeout_seconds: int = 120,
    ) -> dict[str, Any]:
        """PsExec lateral movement from an active C2 implant session."""
        return _post(
            api_url,
            "/c2/psexec",
            {
                "session_id": session_id,
                "target": target,
                "service_name": service_name,
                "bin_path": bin_path,
                "backend": backend,
                "endpoint": endpoint or None,
                "timeout_seconds": timeout_seconds,
            },
            timeout=timeout_seconds + 30,
        )

    return mcp


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the RedStrike MCP server")
    parser.add_argument("--api", default="http://127.0.0.1:8890", help="RedStrike API URL")
    args = parser.parse_args()
    create_mcp(args.api).run()


if __name__ == "__main__":
    main()
