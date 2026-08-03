from __future__ import annotations

import os

import pytest

from cadre_strike.runtime.beachhead import Beachhead, BeachheadRouter, ExecutionPath
from cadre_strike.runtime.ws01_transport import argv_for_plan, wrap_argv_for_ws01


def test_wrap_argv_for_ws01_builds_ssh() -> None:
  os.environ["REDSTRIKE_WS01_SSH_KEY"] = "/tmp/fake-key"
  argv = wrap_argv_for_ws01(["certipy", "find", "-target", "dc01.cadre.local"])
  assert argv[0] == "ssh"
  assert "-i" in argv
  assert "/tmp/fake-key" in argv
  assert argv[-2].startswith("analyst_t1@")
  assert "powershell" in argv[-1]
  assert "certipy" in argv[-1]


def test_argv_for_plan_skips_bash_scripts(tmp_path) -> None:
  root = tmp_path / "linux"
  (root / "campaign-a").mkdir(parents=True)
  script = root / "campaign-a" / "step.sh"
  script.write_text("echo ok\n", encoding="utf-8")
  router = BeachheadRouter(automation_root=root)
  plan = router.plan_step(
    node_id="T003",
    title="test",
    phase=1,
    declared_path="ws01",
    beachhead=Beachhead.WINDOWS,
    script="campaign-a/step.sh",
  )
  assert argv_for_plan(plan) == plan.argv
  assert plan.mechanism == "ws01-exec"


def test_argv_for_plan_wraps_intent(tmp_path) -> None:
  os.environ["REDSTRIKE_WS01_SSH"] = "1"
  os.environ["REDSTRIKE_WS01_SSH_KEY"] = "/tmp/fake-key"
  router = BeachheadRouter(automation_root=tmp_path / "linux")
  plan = router.plan_step(
    node_id="T050",
    title="esc",
    phase=5,
    declared_path="ws01",
    beachhead=Beachhead.WINDOWS,
    script="",
    argv_override=["certipy", "find", "-stdout"],
    intent="certipy.find",
  )
  wrapped = argv_for_plan(plan)
  assert wrapped[0] == "ssh"
  assert wrapped != plan.argv
