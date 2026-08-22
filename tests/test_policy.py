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


def test_load_scope_policy_gated_and_autonomous_profiles() -> None:
    gated = load_scope_policy(path=None, profile="gated")
    auto = load_scope_policy(path=None, profile="autonomous")
    assert gated.allow_high_risk is False
    assert auto.allow_high_risk is True
    assert EngagementMode.OBSERVE in gated.allowed_modes
    assert EngagementMode.VALIDATE in auto.allowed_modes


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


def test_lab_ungated_profile_defaults() -> None:
    policy = load_scope_policy(path=None, profile="lab-ungated")
    assert policy.ungated is True
    assert policy.require_scope is True
    assert policy.allow_high_risk is True
    assert EngagementMode.VALIDATE in policy.allowed_modes


def test_require_scope_fails_without_targets_and_domains() -> None:
    policy = ScopePolicy(require_scope=True, allow_high_risk=True, allowed_modes=[EngagementMode.VALIDATE])
    with pytest.raises(PermissionError, match="allowed_targets"):
        policy.assert_allowed(
            action="intent_execute",
            target="192.168.1.7",
            domain="ignite.local",
            mode=EngagementMode.VALIDATE,
        )
    policy.allowed_targets = ["192.168.1.0/24"]
    with pytest.raises(PermissionError, match="allowed_domains"):
        policy.assert_allowed(
            action="intent_execute",
            target="192.168.1.7",
            domain="ignite.local",
            mode=EngagementMode.VALIDATE,
        )


def test_require_scope_matches_fqdn_under_allowed_domain() -> None:
    policy = ScopePolicy(
        require_scope=True,
        allow_high_risk=True,
        ungated=True,
        allowed_targets=["10.10.10.0/24"],
        allowed_domains=["example.lab"],
        allowed_modes=[EngagementMode.OBSERVE, EngagementMode.VALIDATE],
    )
    policy.assert_allowed(
        action="intent_execute",
        target="dc01.example.lab",
        domain="example.lab",
        mode=EngagementMode.VALIDATE,
    )
    policy.assert_allowed(
        action="domain_users",
        target="10.10.10.10",
        domain="child.example.lab",
        mode=EngagementMode.OBSERVE,
    )
    with pytest.raises(PermissionError, match="Domain"):
        policy.assert_allowed(
            action="domain_users",
            target="10.10.10.10",
            domain="evil.example",
            mode=EngagementMode.OBSERVE,
        )
    with pytest.raises(PermissionError, match="Target"):
        policy.assert_allowed(
            action="domain_users",
            target="172.16.0.1",
            domain="example.lab",
            mode=EngagementMode.OBSERVE,
        )
    with pytest.raises(PermissionError, match="Domain is required"):
        policy.assert_allowed(
            action="domain_users",
            target="10.10.10.10",
            domain=None,
            mode=EngagementMode.OBSERVE,
        )
