from __future__ import annotations


class SharpSCCMBuilder:
    """Typed SharpSCCM.exe argv builder (Branch C)."""

    def __init__(self, binary: str = "SharpSCCM.exe") -> None:
        self.binary = binary

    def get_naa(self, *, server: str) -> list[str]:
        return [self.binary, "get", "naa", "-s", server]

    def get_pxe(self, *, server: str) -> list[str]:
        return [self.binary, "get", "pxe", "-s", server]

    def client_push(self, *, server: str, target: str) -> list[str]:
        return [self.binary, "client-push", "-s", server, "-t", target]

    def exec_cmpivot(self, *, server: str, query: str) -> list[str]:
        return [self.binary, "exec", "-s", server, "-q", query]

    def app_deploy(self, *, server: str, app_name: str, collection: str) -> list[str]:
        return [
            self.binary,
            "app-deploy",
            "-s",
            server,
            "-n",
            app_name,
            "-c",
            collection,
        ]
