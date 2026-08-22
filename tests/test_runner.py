import sys

from redstrike.core.runner import CommandRunner, decode_captured


def test_decode_captured_replaces_invalid_utf8() -> None:
    text = decode_captured(b"ok\x83end")
    assert text.startswith("ok")
    assert text.endswith("end")
    assert "\ufffd" in text or "\x83" not in text.encode("utf-8", errors="replace")


def test_runner_survives_non_utf8_stdout() -> None:
    runner = CommandRunner(timeout_seconds=15)
    result = runner.run(
        [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'ok\\x83end\\n')"]
    )
    assert result.return_code == 0
    assert "ok" in result.stdout
    assert "end" in result.stdout
