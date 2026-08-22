import sys
from types import ModuleType

from redstrike.mcp import server


class FakeMCP:
    def __init__(self, name: str) -> None:
        self.name = name
        self.tools = {}

    def tool(self):
        def decorator(func):
            self.tools[func.__name__] = func
            return func

        return decorator


def test_mcp_exposes_admin_count_and_adcs_tools(monkeypatch) -> None:
    mcp_module = ModuleType("mcp")
    mcp_server_module = ModuleType("mcp.server")
    mcp_fastmcp_module = ModuleType("mcp.server.fastmcp")
    mcp_fastmcp_module.FastMCP = FakeMCP
    fastmcp_module = ModuleType("fastmcp")
    fastmcp_module.FastMCP = FakeMCP
    monkeypatch.setitem(sys.modules, "mcp", mcp_module)
    monkeypatch.setitem(sys.modules, "mcp.server", mcp_server_module)
    monkeypatch.setitem(sys.modules, "mcp.server.fastmcp", mcp_fastmcp_module)
    monkeypatch.setitem(sys.modules, "fastmcp", fastmcp_module)
    monkeypatch.setattr(
        server,
        "_post",
        lambda api_url, path, payload, **_kwargs: {"api_url": api_url, "path": path, "payload": payload},
    )

    mcp = server.create_mcp("http://127.0.0.1:8890")

    assert "find_admin_count_accounts" in mcp.tools
    assert "enumerate_adcs" in mcp.tools
    assert mcp.tools["find_admin_count_accounts"]("dc01")["path"] == "/ad/admin-count"
    assert mcp.tools["enumerate_adcs"]("dc01")["path"] == "/ad/adcs"


def test_mcp_passes_integration_metadata(monkeypatch) -> None:
    mcp_module = ModuleType("mcp")
    mcp_server_module = ModuleType("mcp.server")
    mcp_fastmcp_module = ModuleType("mcp.server.fastmcp")
    mcp_fastmcp_module.FastMCP = FakeMCP
    fastmcp_module = ModuleType("fastmcp")
    fastmcp_module.FastMCP = FakeMCP
    monkeypatch.setitem(sys.modules, "mcp", mcp_module)
    monkeypatch.setitem(sys.modules, "mcp.server", mcp_server_module)
    monkeypatch.setitem(sys.modules, "mcp.server.fastmcp", mcp_fastmcp_module)
    monkeypatch.setitem(sys.modules, "fastmcp", fastmcp_module)
    monkeypatch.setattr(
        server,
        "_post",
        lambda api_url, path, payload, **_kwargs: {"api_url": api_url, "path": path, "payload": payload},
    )

    mcp = server.create_mcp("http://127.0.0.1:8890")
    response = mcp.tools["enumerate_domain_users"](
        "dc01",
        engagement_id="eng-001",
        operator_id="op-1",
        run_id="run-001",
        source_system="redstrike",
        evidence_tags=["users", "phase1"],
    )

    payload = response["payload"]
    assert payload["engagement_id"] == "eng-001"
    assert payload["operator_id"] == "op-1"
    assert payload["run_id"] == "run-001"
    assert payload["source_system"] == "redstrike"
    assert payload["evidence_tags"] == ["users", "phase1"]


def test_mcp_campaign_tools_dispatch(monkeypatch) -> None:
    mcp_module = ModuleType("mcp")
    mcp_server_module = ModuleType("mcp.server")
    mcp_fastmcp_module = ModuleType("mcp.server.fastmcp")
    mcp_fastmcp_module.FastMCP = FakeMCP
    fastmcp_module = ModuleType("fastmcp")
    fastmcp_module.FastMCP = FakeMCP
    monkeypatch.setitem(sys.modules, "mcp", mcp_module)
    monkeypatch.setitem(sys.modules, "mcp.server", mcp_server_module)
    monkeypatch.setitem(sys.modules, "mcp.server.fastmcp", mcp_fastmcp_module)
    monkeypatch.setitem(sys.modules, "fastmcp", fastmcp_module)
    monkeypatch.setattr(
        server,
        "_post",
        lambda api_url, path, payload, timeout=300: {
            "api_url": api_url,
            "path": path,
            "payload": payload,
            "timeout": timeout,
        },
    )

    mcp = server.create_mcp("http://127.0.0.1:8890")
    started = mcp.tools["campaign_start"]("llm-lab", beachhead="windows", profile="gated")["payload"]
    assert started["engagement_id"] == "llm-lab"
    assert started["beachhead"] == "windows"
    assert started["profile"] == "gated"
    assert started["branches"] == "all"

    ran = mcp.tools["campaign_run_phase"]("llm-lab", phase="1-3", beachhead="windows")
    assert ran["timeout"] == 7200
    payload = ran["payload"]
    assert payload["engagement_id"] == "llm-lab"
    assert payload["phase"] == "1-3"
    assert payload["beachhead"] == "windows"


def test_mcp_rejects_non_local_http_api() -> None:
    try:
        server.create_mcp("http://example.com:8890")
        assert False, "Expected non-local HTTP API URL to be rejected"
    except ValueError as exc:
        assert "HTTPS" in str(exc)
