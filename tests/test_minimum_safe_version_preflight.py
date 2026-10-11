"""Tests for the frozen-evidence minimum-version rollout preflight."""

from datetime import datetime, timezone

import pytest

from scripts.check_minimum_safe_version import PreflightError, evaluate


NOW = datetime(2026, 10, 10, 20, tzinfo=timezone.utc)


def evidence(*versions):
    return {
        "network": "devnet",
        "round_number": 334,
        "snapshot_timestamp": "2026-10-10T18:21:14Z",
        "validators": [
            {
                "master_key": f"foundation-{index}",
                "domain": "postfiat.org",
                "domain_verified": True,
                "server_version": version,
            }
            for index, version in enumerate(versions)
        ]
        + [
            {
                "master_key": "community",
                "domain": "example.org",
                "server_version": "1.0.4",
            }
        ],
    }


def test_ready_when_every_foundation_validator_meets_minimum():
    result = evaluate(
        evidence("1.0.9", "1.0.10", "1.0.9+release"),
        "1.0.9",
        "devnet",
        24,
        now=NOW,
    )

    assert result["status"] == "ready"
    assert result["foundationValidatorCount"] == 3
    assert result["blockers"] == []
    assert result["observedVersions"] == {
        "1.0.10": 1,
        "1.0.9": 1,
        "1.0.9+release": 1,
    }


def test_blocked_result_names_each_old_or_missing_foundation_validator():
    result = evaluate(
        evidence("1.0.8", None, "1.0.9-rc1"),
        "1.0.9",
        "devnet",
        24,
        now=NOW,
    )

    assert result["status"] == "blocked"
    assert [blocker["masterKey"] for blocker in result["blockers"]] == [
        "foundation-0",
        "foundation-1",
        "foundation-2",
    ]
    assert result["observedVersions"] == {
        "1.0.8": 1,
        "1.0.9-rc1": 1,
        "<missing>": 1,
    }


@pytest.mark.parametrize(
    ("payload", "minimum", "network", "max_age", "message"),
    [
        (evidence("1.0.9"), "1.0.9-rc1", "devnet", 24, "plain final release"),
        (evidence("1.0.9"), "1.0.9", "testnet", 24, "does not match target"),
        ({"network": "devnet", "round_number": 1, "snapshot_timestamp": "now", "validators": []}, "1.0.9", "devnet", 24, "ISO 8601"),
        ({"network": "devnet", "round_number": 1, "snapshot_timestamp": "2026-10-10T18:21:14Z", "validators": [{"domain": "postfiat.org", "domain_verified": True}]}, "1.0.9", "devnet", 24, "has no master_key"),
        (evidence("1.0.9"), "1.0.9", "devnet", 0, "positive finite"),
    ],
)
def test_invalid_evidence_is_refused(payload, minimum, network, max_age, message):
    with pytest.raises(PreflightError, match=message):
        evaluate(payload, minimum, network, max_age, now=NOW)


def test_unverified_foundation_domain_cannot_satisfy_preflight():
    payload = evidence("1.0.9")
    payload["validators"][0]["domain_verified"] = False

    with pytest.raises(PreflightError, match="no foundation validators"):
        evaluate(payload, "1.0.9", "devnet", 24, now=NOW)


def test_stale_evidence_blocks_even_when_versions_are_ready():
    result = evaluate(
        evidence("1.0.9"),
        "1.0.9",
        "devnet",
        1,
        now=NOW,
    )

    assert result["status"] == "blocked"
    assert result["blockers"] == [
        {"code": "evidence_stale", "ageHours": 1.646111, "maxAgeHours": 1}
    ]
