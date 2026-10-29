"""Pinned CI executor for bounded stacks. Never invoked by the portal HTTP process.

Application code runs only in ordinary CI checks and disposable containers. All
commands are constructed here; source manifests cannot supply shell commands.
"""

import argparse
import hashlib
import os
import re
import secrets
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path
from urllib.request import urlopen

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aegis_platform.canonical import canonical, digest, strict_json  # noqa: E402
from aegis_platform.release import (  # noqa: E402
    ReleaseContext,
    candidate_config,
    file_hash,
    validate_image,
)
from aegis_platform.stack import StackDefinition  # noqa: E402
from aegis_platform.stack_plan import DEPENDENCY_IMAGES, nginx_config  # noqa: E402
from aegis_platform.stack_release import ComponentContext  # noqa: E402
from tooling.ci import checks, inventory_policy  # noqa: E402


def run(args, capture=False, **kwargs):
    result = subprocess.run([str(a) for a in args], check=True, capture_output=capture, **kwargs)
    return result.stdout.decode().strip() if capture else None


def context():
    return ReleaseContext(
        app_id=os.environ["APP_ID"],
        source_repository=os.environ["GITHUB_REPOSITORY"],
        source_repository_id=os.environ["GITHUB_REPOSITORY_ID"],
        source_commit=os.environ["GITHUB_SHA"],
        workflow_run_id=os.environ["GITHUB_RUN_ID"],
        run_attempt=os.environ["GITHUB_RUN_ATTEMPT"],
        platform_commit=os.environ["PLATFORM_COMMIT"],
    )


def service_context(ctx, stack, name):
    return (
        ctx
        if name == stack.primary_service
        else ComponentContext(**ctx.model_dump(), service_name=name)
    )


def load_definition(source):
    path = source / "aegis-stack.json"
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 24576:
        raise ValueError("A bounded regular aegis-stack.json is required")
    stack = StackDefinition.model_validate(strict_json(path.read_bytes()))
    for service in stack.services.values():
        build = source / service.context
        dockerfile = build / service.dockerfile
        if not build.resolve().is_relative_to(
            source.resolve()
        ) or not dockerfile.resolve().is_relative_to(build.resolve()):
            raise ValueError("Build paths escape the source tree")
        if not build.is_dir() or not dockerfile.is_file() or dockerfile.is_symlink():
            raise ValueError("Service build context and Dockerfile must exist")
    return stack


def inspect(image):
    rows = strict_json(run(["docker", "image", "inspect", image], capture=True).encode())
    if len(rows) != 1:
        raise ValueError("Expected one image")
    return rows[0]


def verify_archive_identity(path, image_id, config_id):
    # Classic Docker identifies images by config; the containerd store may use a
    # manifest ID. Bind both forms to the same archived config without conflating them.
    if image_id == config_id:
        return
    with tarfile.open(path) as archive:
        wrapper = strict_json(archive.extractfile("index.json").read(131073))
        roots = wrapper.get("manifests", [])
        if len(roots) != 1 or roots[0].get("digest") != image_id:
            raise ValueError("Docker image ID differs from its archived manifest")
        name = "blobs/sha256/" + image_id.split(":")[1]
        member = archive.getmember(name)
        if not member.isfile() or member.size > 2 * 1024**2:
            raise ValueError("Invalid archived manifest")
        raw = archive.extractfile(member).read()
        if "sha256:" + hashlib.sha256(raw).hexdigest() != image_id:
            raise ValueError("Archived manifest content differs from the image ID")
        if strict_json(raw).get("config", {}).get("digest") != config_id:
            raise ValueError("Archived manifest points to another image config")


def pulled_config(image):
    with tempfile.TemporaryDirectory(prefix="aegis-pull-verify-") as temp:
        archive = Path(temp) / "image.tar"
        run(["docker", "save", "--output", archive, image])
        return candidate_config(archive)[0]


def smoke(stack, images, source=None):
    """Real dependency-backed checks, with no application-owned lifecycle scripts."""
    prefix = "aegis-ci-" + secrets.token_hex(5)
    containers = []
    run(["docker", "network", "create", prefix], capture=True)
    try:
        with tempfile.TemporaryDirectory(prefix="aegis-ci-env-") as temp:
            directory = Path(temp)
            password, redis_password = secrets.token_hex(24), secrets.token_hex(24)

            def start(name, image, env, port=None, command=None, config=None):
                envfile = directory / (name + ".env")
                envfile.touch(mode=0o600)
                if any("\n" in v or "\r" in v for v in env.values()):
                    raise ValueError("Environment values cannot contain newlines")
                envfile.write_text("".join(f"{k}={v}\n" for k, v in env.items()))
                args = [
                    "docker",
                    "run",
                    "-d",
                    "--network",
                    prefix,
                    "--name",
                    prefix + "-" + name,
                    "--network-alias",
                    "ci-" + name,
                    "--env-file",
                    envfile,
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges",
                    "--memory",
                    "256m",
                    "--cpus",
                    "0.5",
                ]
                args += ["--read-only", "--tmpfs", "/tmp:rw,nosuid,size=32m"]
                if name == "postgres":
                    args += [
                        "--user",
                        "70:70",
                        "--tmpfs",
                        "/var/lib/postgresql/data:uid=70,gid=70",
                        "--tmpfs",
                        "/var/run/postgresql:uid=70,gid=70",
                    ]
                elif name == "redis":
                    args += ["--user", "999:999", "--tmpfs", "/data:uid=999,gid=999"]
                elif name == "gateway":
                    args += ["--user", "101:101"]
                else:
                    args += ["--user", "10001:10001"]
                if port:
                    args += ["--publish", f"127.0.0.1::{port}"]
                if config:
                    args += [
                        "--mount",
                        f"type=bind,src={config},dst=/etc/nginx/nginx.conf,readonly",
                    ]
                if name == "gateway":
                    args += ["--entrypoint", "nginx"]
                args += [image, *(command or [])]
                identifier = run(args, capture=True)
                if not re.fullmatch(r"[0-9a-f]{64}", identifier):
                    raise ValueError("Invalid disposable container identity")
                containers.append(identifier)
                if port:
                    address = run(["docker", "port", identifier, f"{port}/tcp"], capture=True)
                    if not re.fullmatch(r"127\.0\.0\.1:[0-9]+", address):
                        raise ValueError("Smoke endpoints must bind to loopback")
                    return "http://" + address
                return identifier

            pg = start(
                "postgres",
                DEPENDENCY_IMAGES["postgres"],
                {
                    "POSTGRES_USER": "commerce",
                    "POSTGRES_DB": "commerce",
                    "POSTGRES_PASSWORD": password,
                },
            )
            start(
                "redis",
                DEPENDENCY_IMAGES["redis"],
                {},
                command=["redis-server", "--requirepass", redis_password],
            )
            for _ in range(40):
                result = subprocess.run(
                    ["docker", "exec", pg, "pg_isready", "-U", "commerce"], capture_output=True
                )
                if result.returncode == 0:
                    break
                time.sleep(0.5)
            else:
                raise ValueError("CI PostgreSQL failed readiness")
            endpoints = {}
            for name, service in stack.services.items():
                env = dict(service.env)
                env.update(
                    {
                        key: f"http://ci-{target}:{stack.services[target].port}"
                        for key, target in service.service_env.items()
                    }
                )
                bindings = {
                    "database-url": f"postgresql://commerce:{password}@ci-postgres:5432/commerce",
                    "redis-url": f"redis://:{redis_password}@ci-redis:6379/0",
                }
                if not set(service.secret_env.values()) <= bindings.keys():
                    raise ValueError("Supported service secrets: database-url and redis-url")
                env.update({key: bindings[ref] for key, ref in service.secret_env.items()})
                endpoints[name] = start(name, images[name], env, port=service.port)
            for name, address in endpoints.items():
                wait_http(address + stack.services[name].health_path)
            # Nginx uses the platform's generated routing, not a source-owned config.
            config = directory / "nginx.conf"
            config.write_text(nginx_config("ci", stack, "127.0.0.11"))
            gateway = start(
                "gateway",
                DEPENDENCY_IMAGES["gateway"],
                {},
                port=8080,
                command=["-g", "daemon off;"],
                config=config,
            )
            wait_http(gateway + "/health")
            for name, service in stack.services.items():
                wait_http(gateway + f"/api/{name}" + service.health_path)
            if source:
                test_image = prefix + "-tests"
                dockerfile = directory / "tests.Dockerfile"
                dockerfile.write_text(
                    "FROM python:3.12.14-slim-trixie@sha256:"
                    "f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f\n"
                    "WORKDIR /app\nCOPY . .\n"
                    "RUN pip install --no-cache-dir --require-hashes -r requirements.txt\n"
                    "ENV PYTHONDONTWRITEBYTECODE=1\nUSER 10001:10001\n"
                    'CMD ["python", "-m", "pytest", "-q", "-p", "no:cacheprovider"]\n'
                )
                (directory / "tests.Dockerfile.dockerignore").write_text(
                    ".git\n.local\n.venv\n.env\n.env.*\n.aws\n.ssh\n__pycache__\n"
                )
                try:
                    run(["docker", "build", "--file", dockerfile, "--tag", test_image, source])
                    run(
                        [
                            "docker",
                            "run",
                            "--rm",
                            "--network",
                            prefix,
                            "--read-only",
                            "--tmpfs",
                            "/tmp:rw,nosuid,size=32m",
                            "--cap-drop",
                            "ALL",
                            "--security-opt",
                            "no-new-privileges",
                            "--pids-limit",
                            "128",
                            "--memory",
                            "384m",
                            "--cpus",
                            "0.5",
                            "--env",
                            "AEGIS_STACK_URL=http://ci-gateway:8080",
                            test_image,
                        ]
                    )
                finally:
                    subprocess.run(
                        ["docker", "image", "rm", "-f", test_image],
                        capture_output=True,
                        check=False,
                    )
            return gateway
    finally:
        for container in reversed(containers):
            subprocess.run(["docker", "rm", "-f", container], capture_output=True, check=False)
        run(["docker", "network", "rm", prefix], capture=True)


def wait_http(url):
    for _ in range(60):
        try:
            with urlopen(url, timeout=2) as response:
                if response.status == 200 and response.url == url:
                    return
        except OSError:
            pass
        time.sleep(0.5)
    raise ValueError("Stack readiness or gateway routing failed")


def build(source, destination, ctx, arch):
    stack = load_definition(source)
    destination.mkdir(parents=True, exist_ok=False)
    images, services = {}, {}
    for name, service in stack.services.items():
        component = service_context(ctx, stack, name)
        image = f"aegis-stack-{ctx.workflow_run_id}-{ctx.run_attempt}-{name}:{arch}"
        args = [
            "docker",
            "build",
            "--provenance=false",
            "--platform",
            "linux/" + arch,
            "--label",
            "io.aegis.app=" + ctx.app_id,
            "--label",
            "io.aegis.service=" + name,
            "--label",
            "org.opencontainers.image.source=https://github.com/" + ctx.source_repository,
            "--label",
            "org.opencontainers.image.revision=" + ctx.source_commit,
            "--file",
            source / service.context / service.dockerfile,
            "--tag",
            image,
        ]
        for key, value in service.build_args.items():
            args += ["--build-arg", f"{key}={value}"]
        run([*args, source / service.context])
        metadata = inspect(image)
        validate_image(metadata, component, arch)
        directory = destination / name
        directory.mkdir()
        run(["docker", "save", "--output", directory / "image.tar", image])
        config_id, _ = candidate_config(directory / "image.tar")
        verify_archive_identity(directory / "image.tar", metadata["Id"], config_id)
        run(
            [
                "trivy",
                "image",
                "--format",
                "json",
                "--list-all-pkgs",
                "--output",
                directory / "image.json",
                image,
            ]
        )
        inventory_policy(strict_json((directory / "image.json").read_bytes()))
        run(
            [
                "trivy",
                "image",
                "--format",
                "cyclonedx",
                "--output",
                directory / "sbom.cdx.json",
                image,
            ]
        )
        services[name] = {
            "image_id": metadata["Id"],
            "image_config_digest": config_id,
            "files": {
                file: file_hash(directory / file)
                for file in ("image.tar", "image.json", "sbom.cdx.json")
            },
        }
        images[name] = image
    smoke(stack, images, source)
    (destination / "candidate.json").write_bytes(
        canonical(
            {
                "schema_version": 1,
                "context": ctx.model_dump(),
                "architecture": arch,
                "stack": stack.model_dump(),
                "stack_sha256": digest(stack.model_dump()),
                "services": services,
                "integration_tests": "passed",
            }
        )
    )


def verify_candidate(directory, ctx, arch):
    data = strict_json((directory / "candidate.json").read_bytes())
    if (
        set(data)
        != {
            "schema_version",
            "context",
            "architecture",
            "stack",
            "stack_sha256",
            "services",
            "integration_tests",
        }
        or type(data["schema_version"]) is not int
    ):
        raise ValueError("Unsupported stack candidate contract")
    stack = StackDefinition.model_validate(data["stack"])
    if (
        data.get("schema_version") != 1
        or data["context"] != ctx.model_dump()
        or data["architecture"] != arch
        or data["stack_sha256"] != digest(stack.model_dump())
        or data["integration_tests"] != "passed"
        or set(data["services"]) != set(stack.services)
    ):
        raise ValueError("Candidate does not match this source/run/profile")
    for name, service in data["services"].items():
        if set(service["files"]) != {"image.tar", "image.json", "sbom.cdx.json"}:
            raise ValueError("Complete service scan/SBOM/archive evidence is required")
        for file, checksum in service["files"].items():
            if file_hash(directory / name / file) != checksum:
                raise ValueError("Downloaded service evidence differs")
        config_id, config = candidate_config(directory / name / "image.tar")
        if config_id != service["image_config_digest"]:
            raise ValueError("Candidate image config differs")
        verify_archive_identity(directory / name / "image.tar", service["image_id"], config_id)
        if config.get("config", {}).get("Labels", {}).get("io.aegis.service") != name:
            raise ValueError("Candidate label belongs to a different stack service")
        validate_image(
            {
                "Id": config_id,
                "Os": config["os"],
                "Architecture": config["architecture"],
                "Config": {"Labels": config["config"].get("Labels", {})},
            },
            service_context(ctx, stack, name),
            arch,
        )
        report = strict_json((directory / name / "image.json").read_bytes())
        if report.get("Metadata", {}).get("ImageID") not in {config_id, service["image_id"]}:
            raise ValueError("Scan describes another service image")
        inventory_policy(report)
    return data, stack


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["checks", "security", "build"])
    parser.add_argument("--source", type=Path, default=Path("source"))
    parser.add_argument("--output", type=Path, default=Path("candidate"))
    args = parser.parse_args()
    architecture = os.environ.get("ARCH", "amd64")
    if architecture not in {"amd64", "arm64"}:
        raise ValueError("Unsupported platform")
    if args.command == "checks":
        load_definition(args.source)
        with tempfile.TemporaryDirectory(prefix="aegis-stack-checks-") as temp:
            checks(args.source.resolve(), Path(temp) / "venv")
    elif args.command == "security":
        from tooling.source_security import scan

        load_definition(args.source)
        scan(args.source.resolve(), Path("source-security.json").resolve())
        run(
            [
                "trivy",
                "fs",
                "--config",
                Path(__file__).resolve().parents[1] / "security/trivy-empty.yaml",
                "--ignorefile",
                Path(__file__).resolve().parents[1] / "security/trivy-empty.ignore",
                "--scanners",
                "vuln",
                "--severity",
                "CRITICAL",
                "--format",
                "json",
                "--output",
                "dependencies.json",
                "--exit-code",
                "1",
                args.source,
            ]
        )
    else:
        build(args.source.resolve(), args.output.resolve(), context(), architecture)
