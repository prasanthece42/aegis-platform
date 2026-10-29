import argparse
import json
import sys
from pathlib import Path

from aegis_platform.catalog import load_catalog
from aegis_platform.contracts import CatalogEntry, DeploymentIntent, DesiredState


def main():
    parser = argparse.ArgumentParser(description="Validate reviewed Aegis application bindings")
    parser.add_argument("--catalog", type=Path, default=Path("catalog"))
    parser.add_argument("--policy", type=Path, default=Path("policies/catalog.json"))
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("validate")
    resolve = commands.add_parser("resolve")
    resolve.add_argument("--app", required=True)
    resolve.add_argument("--environment", choices=["dev", "staging", "prod"], required=True)
    diff = commands.add_parser("check-diff")
    diff.add_argument("--app", required=True)
    diff.add_argument("--environment", choices=["dev", "staging", "prod"], required=True)
    diff.add_argument("--release-tag", required=True)
    diff.add_argument("--paths", type=Path, required=True, help="JSON array of all changed paths")
    commands.add_parser("export-schemas").add_argument(
        "--output", type=Path, default=Path("schemas")
    )
    commands.add_parser("chart-identity").add_argument(
        "--chart", type=Path, default=Path("charts/web-service/1.0.0")
    )
    bootstrap = commands.add_parser("render-bootstrap")
    bootstrap.add_argument("--app", required=True)
    bootstrap.add_argument("--environment", choices=["dev", "staging", "prod"], required=True)
    bootstrap.add_argument("--context", type=Path, required=True)
    bootstrap.add_argument("--bootstrap-policy", type=Path, default=Path("policies/bootstrap.json"))
    bootstrap.add_argument("--chart", type=Path, default=Path("charts/web-service/1.0.0"))
    bootstrap.add_argument("--output", type=Path, required=True)
    release = commands.add_parser("render-release")
    release.add_argument("--app", required=True)
    release.add_argument("--release", type=Path, required=True)
    release.add_argument("--bootstrap-policy", type=Path, default=Path("policies/bootstrap.json"))
    release.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "export-schemas":
            export_schemas(args.output)
            return
        if args.command == "chart-identity":
            from aegis_platform.bootstrap import chart_identity

            print(json.dumps(chart_identity(args.chart), indent=2))
            return
        catalog = load_catalog(args.catalog, args.policy)
        observability_path = args.policy.parent / "observability.json"
        if observability_path.exists():
            from aegis_platform.canonical import strict_json
            from aegis_platform.observability_policy import ObservabilityPolicy

            observability = ObservabilityPolicy.model_validate(
                strict_json(observability_path.read_bytes())
            )
            enrolled = catalog.clusters.get(observability.cluster_id)
            delivery = strict_json((args.policy.parent / "delivery.json").read_bytes())
            if (
                delivery["platform_repository_id"] != observability.platform_repository_id
                or delivery["gitops_repository_id"] != observability.gitops_repository_id
                or delivery["gitops_repository"] != observability.gitops_repository
            ):
                raise ValueError(
                    "Telemetry policy differs from enrolled cluster/repository bindings"
                )
            # Isolated example catalogs do not represent the workstation's active enrollment.
            if args.catalog.resolve() == Path("catalog").resolve() and (
                enrolled is None
                or enrolled.cluster_uid != observability.cluster_uid
                or enrolled.gitops_repository_id != observability.gitops_repository_id
            ):
                raise ValueError("Telemetry policy differs from the active cluster enrollment")
        service_path = args.policy.parent / "observability-service.json"
        if service_path.exists():
            from aegis_platform.canonical import strict_json
            from aegis_platform.observability_service import ObservabilityServicePolicy

            service = ObservabilityServicePolicy.model_validate(
                strict_json(service_path.read_bytes())
            )
            delivery = strict_json((args.policy.parent / "delivery.json").read_bytes())
            if not set(service.operator_user_ids) <= set(delivery["observer_user_ids"]):
                raise ValueError("Telemetry operators must be enrolled local observers")
        owner_path = args.policy.parent / "portal-owner.json"
        if owner_path.exists():
            from aegis_platform.canonical import strict_json
            from aegis_platform.portal_owner import PortalOwnerPolicy

            owner = PortalOwnerPolicy.model_validate(strict_json(owner_path.read_bytes()))
            delivery_path = args.policy.parent / "delivery.json"
            if (
                owner.platform_repository_id
                != strict_json(delivery_path.read_bytes())["platform_repository_id"]
            ):
                raise ValueError("Owner policy differs from the reviewed platform repository")
        if args.command == "render-bootstrap":
            from aegis_platform.bootstrap import bootstrap_plan, write_plan
            from aegis_platform.canonical import strict_json

            files = bootstrap_plan(
                catalog,
                args.app,
                args.environment,
                strict_json(args.context.read_bytes()),
                strict_json(args.bootstrap_policy.read_bytes()),
                args.chart,
            )
            write_plan(files, args.output)
            print("PASS: bootstrap review files rendered; no resources applied")
        elif args.command == "render-release":
            from aegis_platform.bootstrap import release_values, write_plan
            from aegis_platform.canonical import strict_json
            from aegis_platform.release import ReleaseEvidence

            evidence = ReleaseEvidence.model_validate(strict_json(args.release.read_bytes()))
            values = release_values(
                catalog, args.app, "dev", evidence, strict_json(args.bootstrap_policy.read_bytes())
            )
            base = f"applications/{args.app}"
            write_plan(
                {
                    f"{base}/environments/dev/values.yaml": values,
                    f"{base}/environments/dev/release.json": {
                        "schema_version": 1,
                        "app_id": args.app,
                        "environment": "dev",
                        "release_tag": evidence.release_tag,
                        "source_commit": evidence.source_commit,
                        "image": evidence.image,
                        "origin": None,
                        "status": "review-only-live-admission-required",
                    },
                    f"{base}/releases/{evidence.release_tag}.json": evidence.model_dump(),
                },
                args.output,
            )
            print("PASS: DEV review files rendered; live admission and cache proof still required")
        elif args.command == "resolve":
            print(json.dumps(catalog.resolve(args.app, args.environment), indent=2))
        elif args.command == "check-diff":
            from aegis_platform.canonical import strict_json

            paths = strict_json(args.paths.read_bytes())
            if not isinstance(paths, list) or any(not isinstance(p, str) for p in paths):
                raise ValueError("Changed paths must be a complete JSON array of strings")
            catalog.check_delivery_paths(args.app, args.environment, args.release_tag, paths)
            print("PASS: delivery paths belong to the selected app/environment")
        else:
            print(
                f"PASS: {len(catalog.apps)} applications, {len(catalog.clusters)} enrolled clusters"
            )
    except (ValueError, OSError, KeyError, TypeError) as exc:
        print(f"Catalog validation failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from None


def export_schemas(directory: Path):
    from aegis_platform.catalog import CatalogPolicy, Cluster
    from aegis_platform.contracts import RegistrationFields, RegistrationSubmission
    from aegis_platform.delivery import DeliveryPolicy, DeploymentFields, DeploymentSubmission
    from aegis_platform.observability_policy import ObservabilityPolicy
    from aegis_platform.observability_service import ObservabilityServicePolicy
    from aegis_platform.portal_config import LiveConfig
    from aegis_platform.portal_owner import PortalOwnerPolicy
    from aegis_platform.portal_system import PortalSystemPolicy, PortalUploadPolicy
    from aegis_platform.release import PublishedPlatform, ReleaseEvidence
    from aegis_platform.request import RequestTrust

    directory.mkdir(parents=True, exist_ok=True)
    for model, name in [
        (CatalogEntry, "catalog-entry"),
        (DeploymentIntent, "deployment-intent"),
        (DesiredState, "desired-state"),
        (CatalogPolicy, "catalog-policy"),
        (Cluster, "cluster-enrollment"),
        (RegistrationFields, "registration-fields"),
        (RegistrationSubmission, "registration-submission"),
        (ReleaseEvidence, "release-evidence"),
        (PublishedPlatform, "published-platform"),
        (DeliveryPolicy, "delivery-policy"),
        (DeploymentFields, "deployment-fields"),
        (DeploymentSubmission, "deployment-submission"),
        (RequestTrust, "request-trust"),
        (LiveConfig, "portal-config"),
        (PortalSystemPolicy, "portal-system-policy"),
        (PortalUploadPolicy, "portal-uploads-policy"),
        (PortalOwnerPolicy, "portal-owner-policy"),
        (ObservabilityPolicy, "observability-policy"),
        (ObservabilityServicePolicy, "observability-service-policy"),
    ]:
        schema = model.model_json_schema()
        schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
        version = 3 if model is ReleaseEvidence else 1
        (directory / f"{name}.v{version}.json").write_text(json.dumps(schema, indent=2) + "\n")
