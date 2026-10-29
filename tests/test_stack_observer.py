from copy import deepcopy

import pytest

from aegis_platform.contracts import StackRuntime
from aegis_platform.stack_observer import verify_workload
from aegis_platform.stack_plan import DEPENDENCY_IMAGES, manifests
from tests.test_stack import definition


def converged():
    runtime = StackRuntime(
        container_port=8080,
        health_path="/health",
        resource_profile_id="small",
        stack=definition(),
        credentials_secret="orders-api-runtime",
    )
    images = {
        name: f"ghcr.io/example/app/{name}@sha256:" + "a" * 64 for name in runtime.stack.services
    }
    profile = {
        "requests": {"cpu": "100m", "memory": "128Mi"},
        "limits": {"cpu": "500m", "memory": "256Mi"},
    }
    plan = manifests(runtime, "orders-api", "dev", {**images, **DEPENDENCY_IMAGES}, profile)
    expected = next(
        p for p in plan if p["kind"] == "Deployment" and p["metadata"]["name"].endswith("-orders")
    )
    service = next(
        p for p in plan if p["kind"] == "Service" and p["metadata"]["name"].endswith("-orders")
    )
    actual = deepcopy(expected)
    actual["metadata"]["generation"] = 1
    actual["status"] = {
        "observedGeneration": 1,
        "replicas": 2,
        "readyReplicas": 2,
        "updatedReplicas": 2,
        "availableReplicas": 2,
    }
    pods = {"items": []}
    for _ in range(2):
        pod = deepcopy(expected["spec"]["template"])
        pod["status"] = {"containerStatuses": [{"ready": True}]}
        pods["items"].append(pod)
    return expected, actual, service, pods


def test_all_replicas_configuration_and_security_must_converge():
    verify_workload(*converged())


@pytest.mark.parametrize(
    "mutation",
    [
        "image",
        "replicas",
        "host",
        "privileged",
        "env",
        "token",
        "unready",
        "public",
        "extra_container",
        "wrong_generation",
    ],
)
def test_runtime_drift_cannot_be_reported_healthy(mutation):
    expected, actual, service, pods = converged()
    pod = pods["items"][0]["spec"]
    if mutation == "image":
        actual["spec"]["template"]["spec"]["containers"][0]["image"] = "other:latest"
    if mutation == "replicas":
        actual["status"]["readyReplicas"] = 1
    if mutation == "host":
        pod["hostNetwork"] = True
    if mutation == "privileged":
        pod["containers"][0]["securityContext"]["privileged"] = True
    if mutation == "env":
        pod["containers"][0]["envFrom"] = [{"secretRef": {"name": "unapproved"}}]
    if mutation == "token":
        pod["automountServiceAccountToken"] = True
    if mutation == "unready":
        pods["items"][0]["status"]["containerStatuses"][0]["ready"] = False
    if mutation == "public":
        service["spec"]["type"] = "LoadBalancer"
    if mutation == "extra_container":
        pod["containers"].append(deepcopy(pod["containers"][0]))
    if mutation == "wrong_generation":
        actual["status"]["observedGeneration"] = 0
    with pytest.raises(ValueError):
        verify_workload(expected, actual, service, pods)
