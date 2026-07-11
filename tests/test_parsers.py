from cadre_strike.ad.parsers import (
    parse_adcs,
    parse_admin_count,
    parse_computers,
    parse_delegation,
    parse_groups,
    parse_spns,
    parse_users,
)

USERS_SAMPLE = (
    "LDAP 192.168.1.7 389 ignite.local [*] Total users: 3\n"
    "LDAP 192.168.1.7 389 ignite.local - ignite\\alice\n"
    "LDAP 192.168.1.7 389 ignite.local - ignite\\bob\n"
)

GROUPS_SAMPLE = (
    "LDAP 192.168.1.7 389 ignite.local - ignite\\Domain Admins\n"
    "LDAP 192.168.1.7 389 ignite.local - ignite\\Enterprise Admins\n"
)

COMPUTERS_SAMPLE = (
    "LDAP 192.168.1.7 389 ignite.local - DC01$\n"
    "LDAP 192.168.1.7 389 ignite.local - WORKSTATION10$\n"
)

SPN_SAMPLE = (
    "LDAP 192.168.1.7 389 ignite.local - ignite\\svc_sql (SPN: MSSQLSvc/sql.ignite.local:1433)\n"
)

DELEGATION_SAMPLE = (
    "LDAP 192.168.1.7 389 ignite.local [*] Delegation Relationships:\n"
    "LDAP 192.168.1.7 389 ignite.local - ignite\\svc_web (constrained to HTTP/web.ignite.local)\n"
    "LDAP 192.168.1.7 389 ignite.local - ignite\\jump (unconstrained)\n"
)

ADMIN_SAMPLE = (
    "LDAP 192.168.1.7 389 ignite.local - ignite\\admin (adminCount: 1)\n"
)

ADCS_SAMPLE = (
    "LDAP 192.168.1.7 389 ignite.local - ESC1 (Enrollment Agent)\n"
    "LDAP 192.168.1.7 389 ignite.local - ESC2 (...) \n"
)


def test_parse_users_extracts_accounts() -> None:
    entities = parse_users(USERS_SAMPLE)
    assert [e.name for e in entities] == ["ignite\\alice", "ignite\\bob"]
    assert all(e.kind == "user" for e in entities)


def test_parse_groups_extracts_groups() -> None:
    entities = parse_groups(GROUPS_SAMPLE)
    assert "ignite\\Domain Admins" in [e.name for e in entities]


def test_parse_computers_extracts_computers() -> None:
    entities = parse_computers(COMPUTERS_SAMPLE)
    assert "DC01$" in [e.name for e in entities]


def test_parse_spns_extracts_account_and_service() -> None:
    entities = parse_spns(SPN_SAMPLE)
    assert len(entities) == 1
    assert entities[0].account == "ignite\\svc_sql"
    assert entities[0].service == "MSSQLSvc/sql.ignite.local:1433"


def test_parse_delegation_captures_relationship() -> None:
    entities = parse_delegation(DELEGATION_SAMPLE)
    constrained = [e for e in entities if e.delegated_to and "constrained" in e.delegated_to]
    assert constrained
    assert constrained[0].delegating == "ignite\\svc_web"


def test_parse_admin_count_captures_value() -> None:
    entities = parse_admin_count(ADMIN_SAMPLE)
    assert entities[0].name == "ignite\\admin"
    assert entities[0].attributes["adminCount"] == "1"


def test_parse_adcs_extracts_templates() -> None:
    entities = parse_adcs(ADCS_SAMPLE)
    assert [e.name for e in entities] == ["ESC1", "ESC2"]
