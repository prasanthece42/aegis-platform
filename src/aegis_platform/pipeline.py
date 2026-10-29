"""Nine-stage DEV progress projected from exact-attempt jobs and trusted observations.

This projection is display evidence, never deployment admission or authorization.
"""

STAGES = (
    "Validate source",
    "Code quality",
    "Application tests",
    "Source security",
    "Dependency security",
    "Build image",
    "Container security",
    "Publish and verify release",
    "DEV deployment verification",
)


def job_state(job):
    if job.get("status") == "queued":
        return "queued"
    if job.get("status") in {"in_progress", "waiting", "pending"}:
        return "running"
    if job.get("status") != "completed":
        return "unknown"
    return {"success": "passed", "skipped": "skipped", "cancelled": "cancelled"}.get(
        job.get("conclusion"), "failed"
    )


def dev_pipeline(
    jobs, architectures=("amd64", "arm64"), delivery=None, complete=False, stack=False
):
    expected = [
        ["01 Validate source"],
        ["02 Code quality"],
        ["03 Application tests"],
        ["04 Source security"],
        ["05 Dependency security"],
        [f"06 Build image ({arch})" for arch in architectures],
        [f"07 Container security ({arch})" for arch in architectures],
        [f"08 Publish release ({arch})" for arch in architectures] + ["08 Verify release"],
    ]
    if stack:
        expected[1:3] = [["02–03 Validate stack source"] for _ in range(2)]
        expected[3:5] = [["04–05 Stack security"] for _ in range(2)]
        expected[5:7] = [
            [f"06–07 Validate stack ({arch})" for arch in architectures] for _ in range(2)
        ]
    stages = []
    for number, (name, names) in enumerate(zip(STAGES, expected, strict=False), 1):
        matches = [j for j in jobs if j.get("name", "").rsplit(" / ", 1)[-1] in names]
        counts = [sum(j.get("name", "").rsplit(" / ", 1)[-1] == n for j in matches) for n in names]
        states = [job_state(job) for job in matches]
        state = "unknown" if complete else "queued"
        if any(count > 1 for count in counts):
            state = "unknown"
        elif "failed" in states:
            state = "failed"
        elif "cancelled" in states:
            state = "cancelled"
        elif "running" in states:
            state = "running"
        elif all(count == 1 for count in counts):
            state = (
                "passed"
                if all(s == "passed" for s in states)
                else "skipped"
                if "skipped" in states
                else "queued"
            )
        stages.append(
            {
                "number": number,
                "name": name,
                "state": state,
                "message": "Evidence unavailable" if state == "unknown" else "",
            }
        )
    delivery = delivery or {}
    status = delivery.get("status")
    state, message = "queued", "Waiting for a DEV deployment request"
    if delivery.get("health_check_failed"):
        state, message = "failed", "The latest trusted DEV rollout or HTTP health check failed"
    elif status == "healthy":
        if delivery.get("security_verified"):
            state, message = "passed", "Fresh rollout, HTTP health and runtime security verified"
        else:
            state, message = "unknown", "Health verified; fresh runtime security evidence missing"
    elif status in {"accepted", "checking", "reconciling"}:
        state, message = "running", "Waiting for deployment validation and fresh observer evidence"
    elif status in {"closed_unmerged", "superseded"}:
        state, message = "cancelled", "Deployment request closed or superseded"
    stages.append({"number": 9, "name": STAGES[8], "state": state, "message": message})
    return {"schema_version": 1, "environment": "dev", "stages": stages}
