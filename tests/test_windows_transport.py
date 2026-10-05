from __future__ import annotations

import os

from redstrike.runtime.beachhead import Beachhead, BeachheadRouter, OperatorMode
from redstrike.runtime.windows_transport import argv_for_plan, wrap_argv_for_windows


def test_wrap_argv_for_windows_builds_ssh() -> None:
    os.environ["REDSTRIKE_WINDOWS_SSH_KEY"] = "/tmp/fake-key"
    os.environ["REDSTRIKE_WINDOWS_HOST"] = "10.0.0.5"
    os.environ["REDSTRIKE_WINDOWS_USER"] = "labuser"
    argv = wrap_argv_for_windows(["certipy", "find", "-target", "dc.example.lab"])
    assert argv[0] == "ssh"
    assert "-i" in argv
    assert "/tmp/fake-key" in argv
    assert argv[-2] == "labuser@10.0.0.5"
    assert "powershell" in argv[-1]
    assert "certipy" in argv[-1]


def test_argv_for_plan_skips_bash_scripts(tmp_path) -> None:
    root = tmp_path / "linux"
    (root / "campaign-a").mkdir(parents=True)
    script = root / "campaign-a" / "step.sh"
    script.write_text("echo ok\n", encoding="utf-8")
    router = BeachheadRouter(automation_root=root, operator=OperatorMode.LINUX)
    plan = router.plan_step(
        node_id="T003",
        title="test",
        phase=1,
        declared_path="windows",
        beachhead=Beachhead.WINDOWS,
        script="campaign-a/step.sh",
    )
    assert argv_for_plan(plan) == plan.argv
    assert plan.mechanism == "windows-exec"
    assert plan.operator is OperatorMode.LINUX


def test_argv_for_plan_wraps_intent(tmp_path) -> None:
    os.environ["REDSTRIKE_WINDOWS_SSH"] = "1"
    os.environ["REDSTRIKE_WINDOWS_SSH_KEY"] = "/tmp/fake-key"
    router = BeachheadRouter(
        automation_root=tmp_path / "linux", operator=OperatorMode.LINUX
    )
    plan = router.plan_step(
        node_id="T050",
        title="esc",
        phase=5,
        declared_path="windows",
        beachhead=Beachhead.WINDOWS,
        script="",
        argv_override=["certipy", "find", "-stdout"],
        intent="certipy.find",
    )
    wrapped = argv_for_plan(plan)
    assert wrapped[0] == "ssh"
    assert wrapped != plan.argv


def test_operator_windows_native_no_ssh_wrap(tmp_path) -> None:
    os.environ["REDSTRIKE_WINDOWS_SSH"] = "1"
    os.environ["REDSTRIKE_WINDOWS_SSH_KEY"] = "/tmp/fake-key"
    root = tmp_path / "linux"
    (root / "campaign-a").mkdir(parents=True)
    (root / "campaign-a" / "step.sh").write_text("echo ok\n", encoding="utf-8")
    router = BeachheadRouter(automation_root=root, operator=OperatorMode.WINDOWS)

    script_plan = router.plan_step(
        node_id="T003",
        title="script",
        phase=1,
        declared_path="windows",
        beachhead=Beachhead.WINDOWS,
        script="campaign-a/step.sh",
    )
    assert script_plan.mechanism == "local-windows"
    assert script_plan.uses_windows_exec is False
    assert argv_for_plan(script_plan) == script_plan.argv

    intent_plan = router.plan_step(
        node_id="T050",
        title="intent",
        phase=5,
        declared_path="windows",
        beachhead=Beachhead.WINDOWS,
        script="",
        argv_override=["certipy", "find", "-stdout"],
        intent="certipy.find",
    )
    assert intent_plan.uses_windows_exec is False
    assert argv_for_plan(intent_plan) == intent_plan.argv
    assert intent_plan.argv[0] == "certipy"
