"""Display component observations only when trusted, current and fresh."""

from aegis_platform.delivery import timestamp, verify_status


def component_statuses(entry, environment, desired, current, statuses, policy, now):
    result = []
    for obj in desired["effective_values"]["plan"]:
        if obj["kind"] not in {"Deployment", "StatefulSet"}:
            continue
        spec = obj["spec"]
        name = spec["template"]["metadata"]["labels"]["aegis.io/component"]
        row = {
            "name": name,
            "kind": obj["kind"],
            "replicas": spec["replicas"],
            "image": spec["template"]["spec"]["containers"][0]["image"],
            "health": "not_observed",
            "observed_at": None,
        }
        try:
            observed = verify_status(
                statuses,
                f"aegis/{entry.app_id}/{environment}/component/{name}",
                "Healthy " + current.fingerprint,
                current.intent_anchor,
                policy,
                now,
            )
            row.update(
                health="healthy"
                if (now - timestamp(observed["created_at"])).total_seconds() <= 300
                else "stale",
                observed_at=observed["created_at"],
            )
        except (ValueError, KeyError, TypeError):
            pass
        result.append(row)
    return result
