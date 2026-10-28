"""Bounded read-only Kubernetes log bridge; private OTLP, never a public ledger."""

import base64
import collections
import datetime
import hashlib
import ipaddress
import json
import os
import re
import ssl
import time
import urllib.parse
import urllib.request
from pathlib import Path

COLLECTOR = "http://collector.aegis-observability.svc.cluster.local:8081/v1/logs"
SERVICE_ACCOUNT = Path("/var/run/secrets/kubernetes.io/serviceaccount")
NAME = re.compile(r"[a-z0-9][a-z0-9.-]{0,252}")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def timestamp_ns(stamp):
    match = re.fullmatch(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?Z", stamp)
    if not match:
        raise ValueError("Invalid container log timestamp")
    whole = datetime.datetime.strptime(match[1], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=datetime.UTC)
    return int(whole.timestamp()) * 1000000000 + int((match[2] or "").ljust(9, "0"))


def safe_line(line):
    # Header values may contain spaces, commas and multiple cookies; redact the remainder.
    line = re.sub(
        r"(?i)(\b(?:authorization|proxy-authorization|set-cookie|cookie)[\"']?\s*[:=]\s*)[^\r\n]+",
        r"\1[redacted]",
        line,
    )
    line = re.sub(r"(?i)(bearer\s+)[a-z0-9._~+/-]+=*", r"\1[redacted]", line)
    line = re.sub(
        r"(?i)((?:token|password|client_secret|secret|code|state)[\"']?\s*[:=]\s*[\"']?)[^\s\"'&,}]+",
        r"\1[redacted]",
        line,
    )
    return line[:4096].replace("\x00", "")


def attributes(values):
    return [{"key": key, "value": {"stringValue": str(value)}} for key, value in values.items()]


class LogAgent:
    def __init__(self, namespaces, cluster_uid, password, token, ca_file):
        if namespaces is not None and (
            not namespaces
            or any(not NAME.fullmatch(n) or not n.startswith("aegis-") for n in namespaces)
        ):
            raise ValueError("Only explicit Aegis application namespaces may be collected")
        self.namespaces = namespaces
        self.cluster_uid = cluster_uid
        host = os.environ["KUBERNETES_SERVICE_HOST"]
        ipaddress.ip_address(host)
        port = int(os.environ["KUBERNETES_SERVICE_PORT"])
        if not 1 <= port <= 65535:
            raise ValueError("Invalid Kubernetes API port")
        authority = "[" + host + "]" if ":" in host else host
        self.api = f"https://{authority}:{port}"
        self.token = token
        self.password = password
        context = ssl.create_default_context(cafile=ca_file)
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            NoRedirect(),
            urllib.request.HTTPSHandler(context=context),
        )
        self.namespace_cursor = 0
        self.cursors = {}
        self.seen = collections.deque(maxlen=2000)

    def request(self, path):
        request = urllib.request.Request(
            self.api + path, headers={"Authorization": "Bearer " + self.token}
        )
        with self.opener.open(request, timeout=5) as response:
            raw = response.read(2097153)
        if len(raw) > 2097152:
            raise ValueError("Kubernetes response exceeds budget")
        return raw

    def verify_cluster(self):
        namespace = json.loads(self.request("/api/v1/namespaces/kube-system"))
        if namespace["metadata"]["uid"] != self.cluster_uid:
            raise ValueError("Cluster identity differs")

    def collect(self):
        batches = []
        updates = []
        count = 0
        namespaces = self.namespaces
        if namespaces is None:
            discovered = json.loads(self.request("/api/v1/namespaces?limit=100"))
            if discovered.get("metadata", {}).get("continue"):
                raise ValueError("Namespace discovery exceeds budget")
            namespaces = sorted(
                row["metadata"]["name"]
                for row in discovered.get("items", [])
                if row["metadata"]["name"].startswith("aegis-")
                and row["metadata"]["name"] != "aegis-observability"
            )
        if len(namespaces) > 20:
            raise ValueError("Application namespace budget exceeded")
        if not namespaces:
            return batches, updates
        offset = self.namespace_cursor % len(namespaces)
        self.namespace_cursor += 1
        for namespace in namespaces[offset:] + namespaces[:offset]:
            if not NAME.fullmatch(namespace):
                raise ValueError("Invalid application namespace")
            try:
                pods = json.loads(
                    self.request("/api/v1/namespaces/" + namespace + "/pods?limit=100")
                )
            except (OSError, ValueError):
                continue  # A deleted or unavailable namespace must not starve the others.
            if pods.get("metadata", {}).get("continue"):
                raise ValueError("Pod budget exceeded")
            for pod in pods.get("items", []):
                meta = pod["metadata"]
                name = meta["name"]
                uid = meta["uid"]
                if meta["namespace"] != namespace or not NAME.fullmatch(name):
                    raise ValueError("Pod identity differs")
                for status in pod.get("status", {}).get("containerStatuses", []):
                    container = status["name"]
                    if not NAME.fullmatch(container) or not status.get("state", {}).get("running"):
                        continue
                    key = (uid, container, status.get("restartCount", 0))
                    params = {
                        "container": container,
                        "timestamps": "true",
                        "tailLines": 100,
                        "limitBytes": 16384,
                    }
                    if key in self.cursors:
                        params["sinceTime"] = self.cursors[key]
                    else:
                        params["sinceSeconds"] = 60
                    try:
                        raw = self.request(
                            "/api/v1/namespaces/"
                            + namespace
                            + "/pods/"
                            + name
                            + "/log?"
                            + urllib.parse.urlencode(params)
                        )
                    except (OSError, ValueError):
                        continue
                    records = []
                    for line in raw.decode("utf-8", errors="replace").splitlines():
                        stamp, sep, body = line.partition(" ")
                        if not sep:
                            continue
                        try:
                            when = timestamp_ns(stamp)
                        except ValueError:
                            continue
                        identity = hashlib.sha256(
                            (uid + container + stamp + body).encode()
                        ).hexdigest()
                        if identity in self.seen:
                            continue
                        records.append(
                            {
                                "timeUnixNano": str(when),
                                "body": {"stringValue": safe_line(body)},
                                "severityText": "INFO",
                            }
                        )
                        updates.append((key, stamp, identity))
                        count += 1
                        if count >= 100:
                            break
                    if records:
                        batches.append(
                            {
                                "resource": {
                                    "attributes": attributes(
                                        {
                                            "k8s.namespace.name": namespace,
                                            "k8s.pod.name": name,
                                            "k8s.pod.uid": uid,
                                            "k8s.container.name": container,
                                            "service.name": meta.get("labels", {}).get(
                                                "app.kubernetes.io/name", name
                                            ),
                                            "aegis.cluster.uid": self.cluster_uid,
                                            "aegis.log_source": "container",
                                        }
                                    )
                                },
                                "scopeLogs": [
                                    {
                                        "scope": {"name": "aegis.container.logs"},
                                        "logRecords": records,
                                    }
                                ],
                            }
                        )
                    if count >= 100:
                        return batches, updates
        return batches, updates

    def publish(self, batches, updates):
        if not batches:
            return
        raw = json.dumps({"resourceLogs": batches}, separators=(",", ":")).encode()
        if len(raw) > 1048576:
            raise ValueError("Log batch exceeds budget")
        auth = base64.b64encode(("agent:" + self.password).encode()).decode()
        request = urllib.request.Request(
            COLLECTOR,
            data=raw,
            method="POST",
            headers={"Content-Type": "application/json", "Authorization": "Basic " + auth},
        )
        with self.opener.open(request, timeout=5) as response:
            result = json.loads(response.read(65536) or b"{}")
        if int(result.get("partialSuccess", {}).get("rejectedLogRecords", 0)) > 0:
            raise ValueError("Log records were not fully accepted")
        for key, stamp, identity in updates:
            self.cursors[key] = stamp
            self.seen.append(identity)
        if len(self.cursors) > 200:
            self.cursors = dict(list(self.cursors.items())[-200:])


def main():
    agent = LogAgent(
        None,
        os.environ["AEGIS_CLUSTER_UID"],
        Path("/run/log-agent/agent-password").read_text().strip(),
        (SERVICE_ACCOUNT / "token").read_text().strip(),
        str(SERVICE_ACCOUNT / "ca.crt"),
    )
    while True:
        try:
            agent.verify_cluster()
            agent.publish(*agent.collect())
        except (OSError, ValueError, KeyError, TypeError):
            print(
                "Container log collection unavailable; retrying without advancing cursors.",
                flush=True,
            )
        time.sleep(10)


if __name__ == "__main__":
    main()
