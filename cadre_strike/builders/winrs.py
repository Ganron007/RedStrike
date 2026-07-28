from __future__ import annotations


class WinRSBuilder:
    """Typed WinRS (Windows Remote Management) argv builder for lateral movement."""

    def __init__(self, binary: str = "winrs") -> None:
        self.binary = binary

    def run(
        self,
        *,
        target: str,
        command: str,
        username: str | None = None,
        password: str | None = None,
    ) -> list[str]:
        argv = [self.binary, "-r:" + target]
        if username and password:
            argv.extend(["-u:" + username, "-p:" + password])
        elif username:
            argv.append("-u:" + username)
        argv.append(command)
        return argv

    def run_cmd(
        self,
        *,
        target: str,
        command: str = "cmd",
        username: str | None = None,
        password: str | None = None,
    ) -> list[str]:
        return self.run(
            target=target,
            command=command,
            username=username,
            password=password,
        )
