import pytest

from redstrike.core.models import EngagementMode
from redstrike.core.policy import ScopePolicy, load_scope_policy


def test_policy_allows_exact_target_and_domain() -> None:
    policy = ScopePolicy(allowed_targets=["192.168.1.7"], allowed_domains=["ignite.local"])

    policy.assert_allowed(
        action="domain_users",
        target="192.168.1.7",
        domain="ignite.local",
        mode=EngagementMode.OBSERVE,
    )


def test_policy_blocks_out_of_scope_target() -> None:
    policy = ScopePolicy(allowed_targets=["192.168.1.7"])

    with pytest.raises(PermissionError):
        policy.assert_allowed(
            action="domain_users",
            target="192.168.1.200",
            domain=None,
            mode=EngagementMode.OBSERVE,
        )


def test_policy_blocks_high_risk_action_by_default() -> None:
    policy = ScopePolicy()

    with pytest.raises(PermissionError):
        policy.assert_allowed(
            action="password_spray",
            target="192.168.1.7",
            domain=None,
            mode=EngagementMode.ASSESS,
        )


def test_load_scope_policy_supports_common_yaml_conveniences(tmp_path) -> None:
    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text(
        """
        # Inline lists and comments are accepted.
        allowed_targets: ["192.168.1.7", dc01.ignite.local] # scoped assets
        allowed_domains:
          - "ignite.local"
        allowed_modes: [observe, assess]
        allow_high_risk: false
        """,
        encoding="utf-8",
    )

    policy = load_scope_policy(str(scope_path))

    assert policy.allowed_targets == ["192.168.1.7", "dc01.ignite.local"]
    assert policy.allowed_domains == ["ignite.local"]
    assert policy.allowed_modes == [EngagementMode.OBSERVE, EngagementMode.ASSESS]
    assert policy.allow_high_risk is False


def test_load_scope_policy_rejects_orphan_list_item(tmp_path) -> None:
    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text("- 192.168.1.7\n", encoding="utf-8")

    with pytest.raises(ValueError, match="list item has no parent key"):
        load_scope_policy(str(scope_path))


def test_load_scope_policy_profile_defaults() -> None:
    policy = load_scope_policy(path=None, profile="standalone")

    assert policy.allowed_modes == [EngagementMode.OBSERVE, EngagementMode.ASSESS]
    assert policy.allow_high_risk is False
    assert policy.max_concurrent_per_target == 1
    assert policy.max_concurrent_per_domain == 3
    assert policy.cooldown_seconds_per_target == 1.0


def test_load_scope_policy_cadre_campaign_alias() -> None:
    a = load_scope_policy(path=None, profile="campaign")
    b = load_scope_policy(path=None, profile="cadre-campaign")
    assert a.allow_high_risk is True
    assert b.allow_high_risk is True
    assert a.allowed_modes == b.allowed_modes


def test_load_scope_policy_profile_and_scope_file_overlay(tmp_path) -> None:
    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text(
        """
        allowed_targets:
          - 192.168.1.7
        allow_high_risk: false
                max_concurrent_per_target: 2
        """,
        encoding="utf-8",
    )

    policy = load_scope_policy(str(scope_path), profile="validate-gated")

    assert policy.allowed_targets == ["192.168.1.7"]
    assert policy.allowed_modes == [
        EngagementMode.OBSERVE,
        EngagementMode.ASSESS,
        EngagementMode.VALIDATE,
    ]
    assert policy.allow_high_risk is False
    assert policy.max_concurrent_per_target == 2


def test_load_scope_policy_unknown_profile_rejected() -> None:
    with pytest.raises(ValueError, match="Unknown scope policy profile"):
        load_scope_policy(path=None, profile="not-a-profile")
