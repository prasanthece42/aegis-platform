"""Run the enrolled local observer with an explicitly selected operator CLI identity."""

import argparse
import json
import subprocess
import time
from pathlib import Path

from aegis_platform.canonical import strict_json
from aegis_platform.github_api import GitHubAPI
from aegis_platform.local_agent import LocalAgent, LocalConfig
from aegis_platform.worker import DeliveryWorker

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument(
        "--operator-from-gh",
        action="store_true",
        required=True,
        help="Explicitly use the operator's authenticated gh identity; never portal credentials",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare")
    prepare.add_argument("--app", required=True)
    prepare.add_argument("--release-id", required=True)
    observe = commands.add_parser("observe")
    observe.add_argument("--app", required=True)
    observe.add_argument("--environment", choices=["dev", "staging", "prod"], required=True)
    commands.add_parser("watch")
    args = parser.parse_args()
    # Token stays in process memory/subprocess environment, never arguments or files.
    token = subprocess.check_output(
        ["gh", "auth", "token", "--hostname", "github.com"], text=True
    ).strip()
    worker = DeliveryWorker(
        GitHubAPI(token, "prasanthece42/aegis-platform"),
        GitHubAPI(token, "prasanthece42/aegis-gitops"),
        lambda entry: GitHubAPI(token, entry.source.owner + "/" + entry.source.name),
        ROOT,
    )
    agent = LocalAgent(LocalConfig.model_validate(strict_json(args.config.read_bytes())), worker)
    if args.command == "prepare":
        print(json.dumps(agent.prepare(args.app, args.release_id)), flush=True)
    elif args.command == "observe":
        print(json.dumps(agent.observe(args.app, args.environment)), flush=True)
    else:
        prepared = {}
        while True:
            _revision, catalog, _policy, _trust, _bootstrap = worker.snapshot()
            for app_id, entry in catalog.apps.items():
                try:
                    releases = worker.source_factory(entry).repo("GET", "releases?per_page=5")
                    candidates = [
                        release
                        for release in releases
                        if not release["draft"] and not release["prerelease"]
                    ]
                    if candidates:
                        release_id = str(candidates[0]["id"])
                        previous = prepared.get(app_id)
                        if (
                            previous is None
                            or previous[0] != release_id
                            or time.monotonic() - previous[1] > 3600
                        ):
                            print(json.dumps(agent.prepare(app_id, release_id)), flush=True)
                            prepared[app_id] = (release_id, time.monotonic())
                except (ValueError, KeyError, OSError, subprocess.SubprocessError) as exc:
                    print(
                        json.dumps({"app_id": app_id, "cache": "blocked", "reason": str(exc)}),
                        flush=True,
                    )
                for environment in entry.environments:
                    try:
                        print(json.dumps(agent.observe(app_id, environment)), flush=True)
                    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as exc:
                        print(
                            json.dumps(
                                {
                                    "app_id": app_id,
                                    "environment": environment,
                                    "health": "not_verified",
                                    "reason": str(exc),
                                }
                            ),
                            flush=True,
                        )
            time.sleep(60)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
