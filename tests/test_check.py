from pathlib import Path

from redstrike.cli.check import collect_checks, run_check
from redstrike.cli.main import main as redstrike_main


def test_check_core_ok_without_scope_file(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    items = collect_checks(scope_path=tmp_path / "scope.yaml")
    core = [i for i in items if i.required_for_core]
    by_name = {i.name: i for i in core}
    assert by_name["redstrike"].ok
    assert by_name["demo-graph"].ok
    assert by_name["demo-automation"].ok
    scope = next(i for i in items if i.name == "scope")
    assert scope.ok is False


def test_check_cli_json_exit_zero_without_execute_ready(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    code = run_check(scope=str(tmp_path / "scope.yaml"), execute_ready=False, as_json=True)
    assert code == 0
    out = capsys.readouterr().out
    assert '"core_ok": true' in out or '"core_ok": true'.replace(" ", "") in out.replace(" ", "")


def test_redstrike_check_subcommand(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    assert redstrike_main(["check", "--json", "--scope", str(tmp_path / "missing.yaml")]) == 0
