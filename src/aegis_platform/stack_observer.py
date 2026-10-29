"""Pure, component-level convergence and runtime checks for rendered stack resources."""


def subset(expected, actual):
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(
            k in actual and subset(v, actual[k]) for k, v in expected.items()
        )
    if isinstance(expected, list):
        return (
            isinstance(actual, list)
            and len(expected) == len(actual)
            and all(subset(e, a) for e, a in zip(expected, actual, strict=True))
        )
    return expected == actual


def verify_workload(expected, actual, service, pods):
    spec, status = actual["spec"], actual.get("status", {})
    count = expected["spec"]["replicas"]
    fields = ["replicas", "readyReplicas", "updatedReplicas"]
    if expected["kind"] == "Deployment":
        fields.append("availableReplicas")
    if (
        not subset(expected["spec"], spec)
        or status.get("observedGeneration") != actual["metadata"]["generation"]
        or any(status.get(k, 0) != count for k in fields)
    ):
        raise ValueError("Component image, configuration or replicas have not converged")
    selector = spec["selector"]["matchLabels"]
    if (
        service["spec"].get("type", "ClusterIP") != "ClusterIP"
        or service["spec"].get("externalIPs")
        or service["spec"].get("selector") != selector
        or any(p.get("nodePort") for p in service["spec"].get("ports", []))
    ):
        raise ValueError("Stack services must be private and select the approved component")
    selected = [
        p
        for p in pods["items"]
        if not p["metadata"].get("deletionTimestamp")
        and all(p["metadata"].get("labels", {}).get(k) == v for k, v in selector.items())
    ]
    if len(selected) != count:
        raise ValueError("Serving pod count differs from the reviewed stack")
    for pod in [actual["spec"]["template"], *selected]:
        runtime = pod["spec"]
        if (
            not subset(expected["spec"]["template"]["spec"], runtime)
            or any(
                runtime.get(k)
                for k in (
                    "hostNetwork",
                    "hostPID",
                    "hostIPC",
                    "initContainers",
                    "ephemeralContainers",
                )
            )
            or any(
                not set(v) <= {"name", "emptyDir", "configMap", "persistentVolumeClaim"}
                for v in runtime.get("volumes", [])
            )
        ):
            raise ValueError("Component pod differs from the reviewed restricted runtime")
        container = runtime["containers"][0]
        wanted = expected["spec"]["template"]["spec"]["containers"][0]
        if (
            container.get("securityContext", {}).get("privileged", False)
            or container.get("securityContext", {}).get("capabilities", {}).get("add")
            or container.get("securityContext", {}).get("procMount", "Default") != "Default"
            or container.get("command") != wanted.get("command")
            or container.get("args") != wanted.get("args")
            or container.get("lifecycle")
            or container.get("envFrom")
            or any(p.get("hostPort") for p in container.get("ports", []))
        ):
            raise ValueError(
                "Component container has an unapproved privilege or execution override"
            )
    for pod in selected:
        statuses = pod.get("status", {}).get("containerStatuses", [])
        if len(statuses) != 1 or statuses[0].get("ready") is not True:
            raise ValueError("Component serving container is not ready")


def observe_stack(agent, entry, environment, desired):
    values = desired["effective_values"]
    namespace, app_id = entry.environments[environment].namespace, entry.app_id
    pods = agent.get("pods", None, namespace)
    services = {obj["metadata"]["name"]: obj for obj in values["plan"] if obj["kind"] == "Service"}
    components = []
    for obj in values["plan"]:
        kind, name = obj["kind"], obj["metadata"]["name"]
        actual = agent.get(kind.lower(), name, namespace)
        if kind in {"Deployment", "StatefulSet"}:
            live_service = agent.get("service", name, namespace)
            if not subset(services[name]["spec"], live_service["spec"]):
                raise ValueError("Component Service configuration differs")
            verify_workload(obj, actual, live_service, pods)
            components.append(obj["spec"]["template"]["metadata"]["labels"]["aegis.io/component"])
        elif kind == "ConfigMap" and actual.get("data") != obj["data"]:
            raise ValueError("Gateway routing differs from reviewed configuration")
        elif kind == "PersistentVolumeClaim":
            if (
                not subset(obj["spec"], actual["spec"])
                or actual.get("status", {}).get("phase") != "Bound"
            ):
                raise ValueError("Persistent storage is not bound to the reviewed claim")
    for name, component in entry.runtime.stack.services.items():
        agent.http_health(
            f"{app_id}-{name}",
            namespace,
            component.health_path,
            port=component.port,
            strict_contract=False,
        )
    agent.http_health(app_id, namespace, "/health")
    return components
