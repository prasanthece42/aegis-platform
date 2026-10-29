"""Explicitly enrolled local Kind cache and health observer; never applies workloads."""

import io
import json
import os
import re
import select
import subprocess
import tarfile
import tempfile
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from aegis_platform.canonical import digest, strict_json
from aegis_platform.contracts import Contract
from aegis_platform.delivery import cache_fingerprint
from aegis_platform.proposal import current_state
from aegis_platform.release import ReleaseEvidence
from aegis_platform.stack_release import StackReleaseEvidence, parse_release, verify_stack_bundle


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("Service health must not redirect")


def verify_dev_security(deployment, service, pods):
    """Bounded configuration checks on the converged DEV workload and serving pods."""
    labels = deployment["spec"]["selector"]["matchLabels"]
    spec = service["spec"]
    if (
        spec.get("type", "ClusterIP") != "ClusterIP"
        or spec.get("externalIPs")
        or spec.get("selector") != labels
        or any(p.get("nodePort") for p in spec.get("ports", []))
    ):
        raise ValueError("DEV Service must remain private and select the approved workload")
    selected = [
        p
        for p in pods["items"]
        if not p["metadata"].get("deletionTimestamp")
        and all(p["metadata"].get("labels", {}).get(k) == v for k, v in labels.items())
    ]
    if len(selected) != deployment["spec"]["replicas"]:
        raise ValueError("DEV serving pod inventory does not match the converged deployment")
    for pod in [deployment["spec"]["template"], *selected]:
        spec = pod["spec"]
        security = spec.get("securityContext", {})
        if (
            spec.get("automountServiceAccountToken") is not False
            or any(spec.get(k) for k in ("hostNetwork", "hostPID", "hostIPC"))
            or security.get("runAsNonRoot") is not True
            or security.get("runAsUser") != 10001
            or security.get("seccompProfile", {}).get("type") != "RuntimeDefault"
            or any(
                "hostPath" in v or "secret" in v or "projected" in v
                for v in spec.get("volumes", [])
            )
            or spec.get("initContainers")
            or spec.get("ephemeralContainers")
            or len(spec.get("containers", [])) != 1
        ):
            raise ValueError("DEV pod differs from the restricted runtime profile")
        for container in spec["containers"]:
            security = container.get("securityContext", {})
            if (
                container.get("image")
                != deployment["spec"]["template"]["spec"]["containers"][0].get("image")
                or security.get("seccompProfile", {}).get("type", "RuntimeDefault")
                != "RuntimeDefault"
                or security.get("procMount", "Default") != "Default"
                or security.get("allowPrivilegeEscalation") is not False
                or security.get("readOnlyRootFilesystem") is not True
                or security.get("privileged", False)
                or security.get("runAsUser", 10001) != 10001
                or security.get("runAsNonRoot", True) is not True
                or security.get("capabilities", {}).get("add")
                or "ALL" not in security.get("capabilities", {}).get("drop", [])
                or any(p.get("hostPort") for p in container.get("ports", []))
            ):
                raise ValueError("DEV container differs from the restricted runtime profile")


class LocalConfig(Contract):
    kubeconfig: str
    context: str
    cluster_id: str
    cluster_uid: str
    kind_binary: str
    kind_cluster: str
    kind_node: str


def command(args, *, env=None, timeout=60):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=env)
    if result.returncode:
        raise ValueError("Local operator command failed: " + Path(args[0]).name)
    return result.stdout


def normalize_bundle(source: Path, destination: Path, evidence: ReleaseEvidence):
    # Only transport wrapper annotations change. Every registry blob remains byte-exact.
    with tarfile.open(source) as archive, tarfile.open(destination, "w") as output:
        for member in archive:
            if member.isdir():
                output.addfile(member)
                continue
            if not member.isfile():
                raise ValueError("Unsupported OCI archive entry")
            stream = archive.extractfile(member)
            if member.name == "index.json":
                wrapper = strict_json(stream.read())
                roots = wrapper["manifests"]
                if len(roots) != 1 or roots[0]["digest"] != evidence.image.rsplit("@", 1)[1]:
                    raise ValueError("OCI wrapper root differs")
                roots[0].setdefault("annotations", {}).update(
                    {
                        "io.containerd.image.name": evidence.image_name
                        + ":"
                        + evidence.release_tag,
                        "org.opencontainers.image.ref.name": evidence.release_tag,
                    }
                )
                data = json.dumps(wrapper).encode()
                member.size, stream = len(data), io.BytesIO(data)
            output.addfile(member, stream)


class LocalAgent:
    def __init__(self, config: LocalConfig, worker):
        self.config, self.worker = config, worker
        if not Path(config.kubeconfig).is_absolute() or not Path(config.kind_binary).is_absolute():
            raise ValueError("Use explicit absolute kubeconfig and Kind binary paths")
        self.kube = ["kubectl", "--kubeconfig", config.kubeconfig, "--context", config.context]

    def enroll(self, entry, environment, policy):
        target = entry.environments[environment]
        if (
            target.cluster_id != self.config.cluster_id
            or target.cluster_uid != self.config.cluster_uid
        ):
            raise ValueError("App target differs from local cluster enrollment")
        kubeconfig = strict_json(command(self.kube + ["config", "view", "--minify", "-o", "json"]))
        server = urlsplit(kubeconfig["clusters"][0]["cluster"]["server"])
        if server.scheme != "https" or server.hostname not in {"127.0.0.1", "localhost", "::1"}:
            raise ValueError("Refusing a non-loopback Kubernetes API")
        namespace = self.get("namespace", "kube-system")
        if namespace["metadata"]["uid"] != self.config.cluster_uid:
            raise ValueError("Kubernetes namespace UID differs from enrolled cluster identity")
        user = self.worker.gitops.call("GET", "/user")
        if str(user["id"]) not in policy.observer_user_ids:
            raise ValueError("Operator identity is not an approved observer")
        node = self.get("node", self.config.kind_node)
        if node["metadata"]["labels"].get("kubernetes.io/hostname") != self.config.kind_node:
            raise ValueError("Unexpected Kind node identity")

    def get(self, kind, name, namespace=None):
        return strict_json(
            command(
                self.kube
                + (["-n", namespace] if namespace else [])
                + ["get", kind]
                + ([name] if name else [])
                + ["-o", "json"]
            )
        )

    def prepare(self, app_id, release_id):
        from aegis_platform.delivery import admit_release
        from aegis_platform.release import file_hash

        _revision, catalog, policy, _trust, _bootstrap = self.worker.snapshot()
        entry = catalog.apps[app_id]
        self.enroll(entry, "dev", policy)
        source = self.worker.source_factory(entry)
        release = source.repo("GET", "releases/" + release_id)
        assets = [asset for asset in release["assets"] if asset["name"] == "release.json"]
        if len(assets) != 1:
            raise ValueError("Release receipt is missing or ambiguous")
        raw = source.repo("GET", "releases/assets/" + str(assets[0]["id"]), raw=True)
        evidence = parse_release(raw)
        run = source.repo(
            "GET", f"actions/runs/{evidence.workflow_run_id}/attempts/{evidence.run_attempt}"
        )
        admit_release(entry, raw, release, source.repo("GET", ""), run, policy)
        context = f"aegis/{app_id}/{self.config.cluster_id}-cache"
        try:
            with tempfile.TemporaryDirectory(prefix="aegis-cache-") as temporary:
                directory = Path(temporary)
                env = {**os.environ, "GH_TOKEN": source.token, "GH_HOST": "github.com"}
                command(
                    [
                        "gh",
                        "release",
                        "download",
                        evidence.release_tag,
                        "--repo",
                        source.repository,
                        "--pattern",
                        "image.oci.tar",
                        "--dir",
                        str(directory),
                    ],
                    env=env,
                    timeout=300,
                )
                archive = directory / "image.oci.tar"
                if file_hash(archive) != evidence.bundle_sha256:
                    raise ValueError("Retained OCI bundle checksum differs")
                if isinstance(evidence, StackReleaseEvidence):
                    verify_stack_bundle(
                        archive,
                        evidence,
                        consume=lambda _name, graph, child: self.cache_graph(graph, child),
                    )
                    from aegis_platform.stack_plan import DEPENDENCY_IMAGES

                    architecture = self.get("node", self.config.kind_node)["status"]["nodeInfo"][
                        "architecture"
                    ]
                    if architecture not in {"amd64", "arm64"}:
                        raise ValueError("Unsupported enrolled node architecture")
                    for image in DEPENDENCY_IMAGES.values():
                        command(
                            [
                                "docker",
                                "exec",
                                self.config.kind_node,
                                "ctr",
                                "--namespace",
                                "k8s.io",
                                "images",
                                "pull",
                                "--platform",
                                "linux/" + architecture,
                                image,
                            ],
                            timeout=300,
                        )
                else:
                    self.cache_graph(archive, evidence)
        except (ValueError, OSError, subprocess.SubprocessError):
            source.repo(
                "POST",
                "statuses/" + evidence.source_commit,
                {
                    "state": "failure",
                    "context": context,
                    "description": "Exact OCI cache preparation failed",
                },
            )
            raise
        source.repo(
            "POST",
            "statuses/" + evidence.source_commit,
            {
                "state": "success",
                "context": context,
                "description": "cachefp:" + cache_fingerprint(entry, "dev", evidence).split(":")[1],
            },
        )
        return {
            "app_id": app_id,
            "release_id": release_id,
            "image": evidence.image,
            "cache": "verified",
        }

    def cache_graph(self, archive, evidence):
        from aegis_platform.release import verify_oci_bundle

        directory = archive.parent
        root = evidence.image.rsplit("@", 1)[1]
        verify_oci_bundle(archive, root, evidence.platforms)
        imported = directory / "kind-import.oci.tar"
        normalize_bundle(archive, imported, evidence)
        verify_oci_bundle(imported, root, evidence.platforms)
        command(
            [
                self.config.kind_binary,
                "load",
                "image-archive",
                str(imported),
                "--name",
                self.config.kind_cluster,
            ],
            timeout=300,
        )
        ctr = [
            "docker",
            "exec",
            self.config.kind_node,
            "ctr",
            "--namespace",
            "k8s.io",
            "images",
        ]
        rows = command(ctr + ["list"]).splitlines()
        matching = [
            line.split()[0] for line in rows if len(line.split()) > 2 and line.split()[2] == root
        ]
        if not matching:
            raise ValueError("Containerd did not retain the exact registry index")
        command(ctr + ["tag", "--force", matching[0], evidence.image])
        rows = command(ctr + ["list"]).splitlines()
        if not any(
            len(row.split()) > 2 and row.split()[0] == evidence.image and row.split()[2] == root
            for row in rows
        ):
            raise ValueError("Containerd digest reference verification failed")

    def observe(self, app_id, environment):
        _revision, catalog, policy, _trust, _bootstrap = self.worker.snapshot()
        entry = catalog.apps[app_id]
        self.enroll(entry, environment, policy)
        target = entry.environments[environment]
        _head, files, anchor = self.worker.target_files(entry, environment)
        current = current_state(entry, environment, files, anchor, digest(policy.model_dump()))
        if current is None:
            raise ValueError("Application has no desired-state intent")
        pointer = strict_json(files[target.values_path.rsplit("/", 1)[0] + "/release.json"])
        desired = pointer["desired_state"]
        try:
            argo = self.get("application", target.argo_application, "argocd")
            binding = desired["controller_bindings"][
                f"argocd/applications/{target.argo_application}.json"
            ]
            if argo["spec"] != binding["spec"]:
                raise ValueError(
                    "Live Argo Application binding differs from reviewed Git configuration"
                )
            status = argo.get("status", {})
            revision = status.get("sync", {}).get("revision", "")
            if (
                status.get("health", {}).get("status") != "Healthy"
                or status.get("sync", {}).get("status") != "Synced"
                or not re.fullmatch(r"[0-9a-f]{40}", revision)
            ):
                raise ValueError("Argo has not reported Healthy/Synced")
            for path, data in {
                target.values_path: files[target.values_path],
                **{p: files[p] for p in desired["controller_bindings"]},
            }.items():
                if self.worker.gitops.file(path, revision) != data:
                    raise ValueError(
                        "Observed Argo revision has different app-specific configuration"
                    )
            components = []
            if entry.runtime.profile_id == "python312-multiservice":
                from aegis_platform.stack_observer import observe_stack

                components = observe_stack(self, entry, environment, desired)
            else:
                deployment = self.get("deployment", app_id, target.namespace)
                replicas = desired["effective_values"]["replicaCount"]
                observed = deployment.get("status", {})
                containers = deployment["spec"]["template"]["spec"]["containers"]
                expected_image = (
                    desired["effective_values"]["image"]["repository"]
                    + "@"
                    + current.image_root_digest
                )
                if (
                    len(containers) != 1
                    or containers[0]["image"] != expected_image
                    or observed.get("observedGeneration", 0) != deployment["metadata"]["generation"]
                    or deployment["spec"]["replicas"] != replicas
                    or any(
                        observed.get(field, 0) != replicas
                        for field in [
                            "replicas",
                            "updatedReplicas",
                            "readyReplicas",
                            "availableReplicas",
                        ]
                    )
                ):
                    raise ValueError("Deployment replicas/image/generation have not converged")
                if environment == "dev":
                    verify_dev_security(
                        deployment,
                        self.get("service", app_id, target.namespace),
                        self.get("pods", None, target.namespace),
                    )
                self.http_health(app_id, target.namespace, entry.runtime.health_path)
        except (ValueError, KeyError, OSError, subprocess.SubprocessError):
            self.worker.gitops.repo(
                "POST",
                "statuses/" + current.intent_anchor,
                {
                    "state": "failure",
                    "context": f"aegis/{app_id}/{environment}-health",
                    "description": "App-specific rollout or HTTP health has not converged",
                },
            )
            raise
        for component in components:
            self.worker.gitops.repo(
                "POST",
                "statuses/" + current.intent_anchor,
                {
                    "state": "success",
                    "context": f"aegis/{app_id}/{environment}/component/{component}",
                    "description": "Healthy " + current.fingerprint,
                },
            )
        if environment == "dev":
            self.worker.gitops.repo(
                "POST",
                "statuses/" + current.intent_anchor,
                {
                    "state": "success",
                    "context": f"aegis/{app_id}/dev-security",
                    "description": "Restricted runtime " + current.fingerprint,
                },
            )
        self.worker.gitops.repo(
            "POST",
            "statuses/" + current.intent_anchor,
            {
                "state": "success",
                "context": f"aegis/{app_id}/{environment}-health",
                "description": "Healthy " + current.fingerprint,
            },
        )
        return {
            "app_id": app_id,
            "environment": environment,
            "fingerprint": current.fingerprint,
            "intent_anchor": current.intent_anchor,
            "argo_revision": revision,
            "observed_at": datetime.now(UTC).isoformat(),
            "health": "healthy",
        }

    def http_health(self, app_id, namespace, path, *, port=80, strict_contract=True):
        process = subprocess.Popen(
            self.kube
            + [
                "-n",
                namespace,
                "port-forward",
                "service/" + app_id,
                f"0:{port}",
                "--address",
                "127.0.0.1",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        try:
            if not select.select([process.stdout], [], [], 10)[0]:
                raise ValueError("Service probe forward did not start")
            line = process.stdout.readline()
            match = re.search(r"Forwarding from 127\.0\.0\.1:([0-9]+)", line)
            if not match:
                raise ValueError("Service probe forward failed")
            request = urllib.request.Request(f"http://127.0.0.1:{match[1]}" + path)
            opener = urllib.request.build_opener(NoRedirect)
            with opener.open(request, timeout=5) as response:
                if (
                    response.url != request.full_url
                    or response.status != 200
                    or (strict_contract and strict_json(response.read(4096)) != {"status": "ok"})
                ):
                    raise ValueError("Service HTTP health failed")
        finally:
            process.terminate()
            process.wait(timeout=10)
