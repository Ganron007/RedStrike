from __future__ import annotations

import argparse
import ipaddress
from urllib.parse import urlparse
from typing import Any

import requests


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


def _post(api_url: str, path: str, payload: dict[str, Any]) -> dict[str, Any]:
    _validate_api_url(api_url)
    response = requests.post(f"{api_url.rstrip('/')}{path}", json=payload, timeout=300)
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
    except Exception:
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

    return mcp


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the RedStrike MCP server")
    parser.add_argument("--api", default="http://127.0.0.1:8890", help="RedStrike API URL")
    args = parser.parse_args()
    create_mcp(args.api).run()


if __name__ == "__main__":
    main()
