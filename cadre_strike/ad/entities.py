from __future__ import annotations

from pydantic import BaseModel


class ADEntity(BaseModel):
    kind: str
    name: str
    attributes: dict[str, str] = {}


class UserEntity(ADEntity):
    kind: str = "user"


class GroupEntity(ADEntity):
    kind: str = "group"


class ComputerEntity(ADEntity):
    kind: str = "computer"


class SpnEntity(ADEntity):
    kind: str = "spn"
    account: str | None = None
    service: str | None = None


class DelegationEntity(ADEntity):
    kind: str = "delegation"
    delegating: str | None = None
    delegated_to: str | None = None


class AdminCountEntity(ADEntity):
    kind: str = "admin_count"


class AdcsEntity(ADEntity):
    kind: str = "adcs"
