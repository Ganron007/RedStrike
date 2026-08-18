from __future__ import annotations

from pydantic import SecretStr


def extend_user_pass(
    argv: list[str],
    *,
    username: str | None = None,
    password: str | SecretStr | None = None,
    nt_hash: str | SecretStr | None = None,
    domain: str | None = None,
    user_flag: str = "-u",
    pass_flag: str = "-p",
    hash_flag: str = "-H",
    domain_flag: str = "-d",
) -> list[str]:
    out = list(argv)
    if username:
        out.extend([user_flag, username])
    if password:
        value = password.get_secret_value() if isinstance(password, SecretStr) else password
        out.extend([pass_flag, value])
    if nt_hash:
        value = nt_hash.get_secret_value() if isinstance(nt_hash, SecretStr) else nt_hash
        out.extend([hash_flag, value])
    if domain:
        out.extend([domain_flag, domain])
    return out


def secret_value(value: str | SecretStr | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, SecretStr):
        return value.get_secret_value()
    return value
