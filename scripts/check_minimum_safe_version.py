"""Check frozen validator evidence before raising MINIMUM_SAFE_VERSION.

The input is the public ``inputs/validator_evidence.json`` artifact from the
latest normal round in the target environment.  Exit 0 means every foundation
validator reports the requested final release or newer, exit 1 means rollout is
still blocked, and exit 2 means the evidence is unusable.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scoring_service.server_version import (  # noqa: E402
    meets_minimum_version,
    parse_release_version,
)


class PreflightError(ValueError):
    """Raised when frozen evidence cannot support a rollout decision."""


def evaluate(
    payload: Any,
    minimum_text: str,
    expected_network: str,
    max_age_hours: float,
    foundation_domain: str = "postfiat.org",
    now: datetime | None = None,
) -> dict[str, Any]:
    minimum = parse_release_version(minimum_text)
    if minimum is None:
        raise PreflightError("minimum must be a plain final release such as 1.0.9")
    if not isinstance(payload, dict):
        raise PreflightError("evidence must be a JSON object")

    network = payload.get("network")
    round_number = payload.get("round_number")
    snapshot_timestamp = payload.get("snapshot_timestamp")
    validators = payload.get("validators")
    if not isinstance(network, str) or not network:
        raise PreflightError("evidence.network must be a non-empty string")
    if network != expected_network:
        raise PreflightError(
            f"evidence network {network!r} does not match target {expected_network!r}"
        )
    if not isinstance(round_number, int) or isinstance(round_number, bool):
        raise PreflightError("evidence.round_number must be an integer")
    if not isinstance(snapshot_timestamp, str) or not snapshot_timestamp:
        raise PreflightError("evidence.snapshot_timestamp must be a non-empty string")
    if not math.isfinite(max_age_hours) or max_age_hours <= 0:
        raise PreflightError("max age hours must be a positive finite number")
    try:
        snapshot_at = datetime.fromisoformat(snapshot_timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PreflightError("evidence.snapshot_timestamp must be ISO 8601") from exc
    if snapshot_at.tzinfo is None:
        raise PreflightError("evidence.snapshot_timestamp must include a timezone")
    current_time = now or datetime.now(timezone.utc)
    if current_time.tzinfo is None:
        raise PreflightError("current time must include a timezone")
    age_hours = (current_time - snapshot_at).total_seconds() / 3600
    if age_hours < -(5 / 60):
        raise PreflightError("evidence.snapshot_timestamp is more than 5 minutes ahead")
    if not isinstance(validators, list):
        raise PreflightError("evidence.validators must be an array")

    foundation: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, validator in enumerate(validators):
        if not isinstance(validator, dict):
            raise PreflightError(f"evidence.validators[{index}] must be an object")
        if (
            validator.get("domain") != foundation_domain
            or validator.get("domain_verified") is not True
        ):
            continue
        master_key = validator.get("master_key")
        if not isinstance(master_key, str) or not master_key:
            raise PreflightError(
                f"foundation validator at evidence.validators[{index}] has no master_key"
            )
        if master_key in seen:
            raise PreflightError(f"duplicate foundation master_key: {master_key}")
        seen.add(master_key)
        foundation.append(validator)

    if not foundation:
        raise PreflightError(
            f"no foundation validators matched domain {foundation_domain!r}"
        )

    blockers = []
    if age_hours > max_age_hours:
        blockers.append(
            {
                "code": "evidence_stale",
                "ageHours": round(age_hours, 6),
                "maxAgeHours": max_age_hours,
            }
        )
    versions: Counter[str] = Counter()
    for validator in sorted(foundation, key=lambda item: item["master_key"]):
        version = validator.get("server_version")
        version_label = version if isinstance(version, str) and version else "<missing>"
        versions[version_label] += 1
        if not isinstance(version, str) or not meets_minimum_version(version, minimum):
            blockers.append(
                {
                    "code": "foundation_version_below_minimum",
                    "masterKey": validator["master_key"],
                    "serverVersion": version if isinstance(version, str) else None,
                }
            )

    return {
        "status": "ready" if not blockers else "blocked",
        "network": network,
        "roundNumber": round_number,
        "snapshotTimestamp": snapshot_timestamp,
        "evidenceAgeHours": round(max(age_hours, 0), 6),
        "maxAgeHours": max_age_hours,
        "minimumSafeVersion": minimum_text,
        "foundationDomain": foundation_domain,
        "foundationValidatorCount": len(foundation),
        "observedVersions": dict(sorted(versions.items())),
        "blockers": blockers,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--minimum", required=True)
    parser.add_argument("--network", required=True)
    parser.add_argument("--max-age-hours", required=True, type=float)
    parser.add_argument("--foundation-domain", default="postfiat.org")
    args = parser.parse_args()

    try:
        payload = json.loads(args.evidence.read_text())
        result = evaluate(
            payload,
            args.minimum,
            args.network,
            args.max_age_hours,
            args.foundation_domain,
        )
    except (OSError, json.JSONDecodeError, PreflightError) as exc:
        print(
            json.dumps(
                {"status": "invalid", "error": str(exc)},
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 2

    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"] == "ready" else 1


if __name__ == "__main__":
    raise SystemExit(main())
