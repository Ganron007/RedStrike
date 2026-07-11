from __future__ import annotations

import re
from collections.abc import Callable

from cadre_strike.ad.entities import (
    AdminCountEntity,
    AdcsEntity,
    ADEntity,
    ComputerEntity,
    DelegationEntity,
    GroupEntity,
    SpnEntity,
    UserEntity,
)

# Entries are prefixed by a dash (optionally led by a bullet/space). The dash is
# required so header lines without one (e.g. "[*] Total users: 3") are skipped.
_LINE = re.compile(r"(?:^|[*\s])-+\s+(\S.*?)(?:\s*\([^)]*\))?\s*$")
_SPN = re.compile(r"\(SPN:\s*([^)]+)\)")
_DELEG = re.compile(r"(?:^|[*\s])-+\s+(\S.*?)\s*(?:\(([^)]*)\))?\s*$")
_ADMIN = re.compile(r"(?:^|[*\s])-+\s+(\S.*?)\s*\(adminCount:\s*(\d+)\)\s*$")
_ADCS = re.compile(r"(?:^|[*\s])-+\s+(\S.*?)\s*(?:\(([^)]*)\))?\s*$")

_HEADER_TOKENS = {
    "username",
    "total",
    "passwordlastset",
    "lastlogon",
    "name",
    "members",
    "description",
}


def parse_users(output: str) -> list[UserEntity]:
    found: list[UserEntity] = []
    for line in output.splitlines():
        match = _LINE.search(line)
        if not match:
            continue
        name = match.group(1)
        if name.lower() in _HEADER_TOKENS:
            continue
        found.append(UserEntity(name=name))
    return found


def parse_groups(output: str) -> list[GroupEntity]:
    found: list[GroupEntity] = []
    for line in output.splitlines():
        match = _LINE.search(line)
        if not match:
            continue
        name = match.group(1)
        if name.lower() in _HEADER_TOKENS:
            continue
        found.append(GroupEntity(name=name))
    return found


def parse_computers(output: str) -> list[ComputerEntity]:
    found: list[ComputerEntity] = []
    for line in output.splitlines():
        match = _LINE.search(line)
        if not match:
            continue
        name = match.group(1)
        if name.lower() in _HEADER_TOKENS:
            continue
        found.append(ComputerEntity(name=name))
    return found


def parse_spns(output: str) -> list[SpnEntity]:
    found: list[SpnEntity] = []
    for line in output.splitlines():
        spn_match = _SPN.search(line)
        if not spn_match:
            continue
        service = spn_match.group(1).strip()
        account = None
        line_match = _LINE.search(line)
        if line_match:
            account = line_match.group(1)
        found.append(SpnEntity(name=service, account=account, service=service))
    return found


def parse_delegation(output: str) -> list[DelegationEntity]:
    found: list[DelegationEntity] = []
    for line in output.splitlines():
        match = _DELEG.search(line)
        if not match:
            continue
        account = match.group(1)
        detail = (match.group(2) or "").strip()
        found.append(
            DelegationEntity(
                name=account,
                delegating=account,
                delegated_to=detail or None,
                attributes={"detail": detail} if detail else {},
            )
        )
    return found


def parse_admin_count(output: str) -> list[AdminCountEntity]:
    found: list[AdminCountEntity] = []
    for line in output.splitlines():
        match = _ADMIN.search(line)
        if not match:
            continue
        name = match.group(1)
        count = match.group(2)
        found.append(AdminCountEntity(name=name, attributes={"adminCount": count}))
    return found


def parse_adcs(output: str) -> list[AdcsEntity]:
    found: list[AdcsEntity] = []
    for line in output.splitlines():
        match = _ADCS.search(line)
        if not match:
            continue
        name = match.group(1)
        detail = (match.group(2) or "").strip()
        found.append(AdcsEntity(name=name, attributes={"detail": detail} if detail else {}))
    return found


def parse_for_action(action: str, output: str) -> list[ADEntity]:
    mapping: dict[str, Callable] = {
        "domain_users": parse_users,
        "domain_groups": parse_groups,
        "domain_computers": parse_computers,
        "kerberoastable": parse_spns,
        "delegation": parse_delegation,
        "admin_count": parse_admin_count,
        "adcs_enum": parse_adcs,
    }
    parser = mapping.get(action)
    if not parser:
        return []
    return parser(output)
