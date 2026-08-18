from pydantic import SecretStr

from redstrike.ad.netexec import NetExecCommandBuilder
from redstrike.core.runner import redact_argv


def test_builder_returns_argument_vector_not_shell_string() -> None:
    builder = NetExecCommandBuilder()

    argv = builder.users(
        target="192.168.1.7",
        username="raaz",
        password=SecretStr("Password@1"),
        domain="ignite.local",
        kdc_host=None,
    )

    assert argv == [
        "nxc",
        "ldap",
        "192.168.1.7",
        "-u",
        "raaz",
        "-p",
        "Password@1",
        "-d",
        "ignite.local",
        "--users",
    ]


def test_redact_argv_masks_passwords_and_hashes() -> None:
    assert redact_argv(["nxc", "smb", "dc", "-p", "secret", "-H", "hash"]) == [
        "nxc",
        "smb",
        "dc",
        "-p",
        "***REDACTED***",
        "-H",
        "***REDACTED***",
    ]


def test_builder_supports_adcs_enumeration() -> None:
    builder = NetExecCommandBuilder()

    argv = builder.adcs_enum(target="dc01.ignite.local", username="raaz", domain="ignite.local")

    assert argv == [
        "nxc",
        "ldap",
        "dc01.ignite.local",
        "-u",
        "raaz",
        "-d",
        "ignite.local",
        "--adcs",
    ]
