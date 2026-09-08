#!/usr/bin/env python3
"""Create Cisco Secure Access RDP private resources from CLI values or CSV.

The program never writes unless --apply is supplied. Credentials are read only
from CISCO_SECURE_ACCESS_CLIENT_ID and CISCO_SECURE_ACCESS_CLIENT_SECRET.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import json
import os
import re
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


API_ROOT = "https://api.sse.cisco.com"
TOKEN_URL = f"{API_ROOT}/auth/v2/token"
RESOURCE_LIMIT = 1000
RESOURCE_NAME_LIMIT = 50
RDP_PROTOCOL = "RDP-TCP"
RDP_PORT = "3389"
FQDN_RE = re.compile(
    r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    re.IGNORECASE,
)


class ImporterError(RuntimeError):
    """A safe, user-facing importer failure."""


class ApiError(ImporterError):
    def __init__(self, status: int, message: str, body: Any = None):
        self.status = status
        self.body = body
        details = ""
        if isinstance(body, dict):
            validation_errors = body.get("validationErrors")
            if isinstance(validation_errors, dict) and validation_errors:
                rendered = "; ".join(
                    f"{field}: {detail}"
                    for field, detail in validation_errors.items()
                )
                details = f" ({rendered})"
        super().__init__(f"Cisco API request failed ({status}): {message}{details}")


class RunFailed(ImporterError):
    """A failed import with the structured results completed before failure."""

    def __init__(self, message: str, results: list["Result"]):
        self.results = results
        super().__init__(message)


@dataclass(frozen=True)
class ResourceInput:
    fqdn: str
    line: int

    @property
    def resource_name(self) -> str:
        return derive_resource_name(self.fqdn)


@dataclass
class Result:
    fqdn: str
    resource_name: str
    protocol: str
    port: str
    dns_server_group: str
    dns_server_id: int
    status: str
    resource_id: int | None = None
    message: str | None = None


@dataclass(frozen=True)
class DnsServerChoice:
    connector_group_name: str
    connector_group_id: int
    dns_server_id: int
    domains: str


def normalise_fqdn(value: str) -> str:
    fqdn = value.strip().rstrip(".").lower()
    if not FQDN_RE.fullmatch(fqdn):
        raise ImporterError(f"Invalid FQDN: {value!r}")
    return fqdn


def derive_resource_name(fqdn: str) -> str:
    """Return a Cisco-valid, deterministic name no longer than 50 characters."""
    slug = fqdn.replace(".", "-")
    candidate = f"rdp-{slug}"
    if len(candidate) <= RESOURCE_NAME_LIMIT:
        return candidate
    suffix = "-" + hashlib.sha256(fqdn.encode("utf-8")).hexdigest()[:8]
    prefix = "rdp-"
    keep = RESOURCE_NAME_LIMIT - len(prefix) - len(suffix)
    return f"{prefix}{slug[:keep]}{suffix}"


def build_payload(item: ResourceInput, dns_server_id: int) -> dict[str, Any]:
    return {
        "name": item.resource_name,
        "description": f"RDP resource for {item.fqdn}",
        "accessTypes": [
            {"type": "client", "reachableAddresses": [item.fqdn]}
        ],
        "resourceAddresses": [
            {
                "destinationAddr": [item.fqdn],
                "protocolPorts": [{"protocol": RDP_PROTOCOL, "ports": RDP_PORT}],
            }
        ],
        "dnsServerId": dns_server_id,
    }


def parse_csv(path: Path) -> list[ResourceInput]:
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            if reader.fieldnames is None:
                raise ImporterError("CSV is empty or has no header row")
            headers = {header.strip() for header in reader.fieldnames if header}
            required = {"fqdn"}
            if not required.issubset(headers):
                raise ImporterError("CSV requires the header: fqdn")
            rows: list[ResourceInput] = []
            for line, row in enumerate(reader, start=2):
                if not any((value or "").strip() for value in row.values()):
                    continue
                fqdn_value = (row.get("fqdn") or "").strip()
                if not fqdn_value:
                    raise ImporterError(f"CSV line {line} requires fqdn")
                rows.append(ResourceInput(normalise_fqdn(fqdn_value), line))
    except OSError as exc:
        raise ImporterError(f"Cannot read CSV {path}: {exc}") from exc
    return validate_inputs(rows)


def validate_inputs(items: Iterable[ResourceInput]) -> list[ResourceInput]:
    rows = list(items)
    if not rows:
        raise ImporterError("At least one private resource is required")
    if len(rows) > RESOURCE_LIMIT:
        raise ImporterError(
            f"CSV contains {len(rows)} rows; Cisco permits at most {RESOURCE_LIMIT} private resources"
        )
    seen_fqdns: set[str] = set()
    seen_names: set[str] = set()
    for item in rows:
        if item.fqdn in seen_fqdns:
            raise ImporterError(f"Duplicate FQDN {item.fqdn!r} on line {item.line}")
        if item.resource_name in seen_names:
            raise ImporterError(
                f"Derived duplicate resource name {item.resource_name!r} on line {item.line}"
            )
        seen_fqdns.add(item.fqdn)
        seen_names.add(item.resource_name)
    return rows


class CiscoSecureAccessClient:
    def __init__(
        self,
        client_id: str,
        client_secret: str,
        organization_id: str | None = None,
        api_root: str = API_ROOT,
        retries: int = 3,
    ) -> None:
        self.client_id = client_id
        self.client_secret = client_secret
        self.organization_id = organization_id
        self.api_root = api_root.rstrip("/")
        self.retries = retries
        self.access_token: str | None = None

    @classmethod
    def from_environment(cls) -> "CiscoSecureAccessClient":
        client_id = os.getenv("CISCO_SECURE_ACCESS_CLIENT_ID")
        client_secret = os.getenv("CISCO_SECURE_ACCESS_CLIENT_SECRET")
        if not client_id or not client_secret:
            raise ImporterError(
                "Set CISCO_SECURE_ACCESS_CLIENT_ID and "
                "CISCO_SECURE_ACCESS_CLIENT_SECRET before running."
            )
        return cls(
            client_id,
            client_secret,
            os.getenv("CISCO_SECURE_ACCESS_ORG_ID"),
        )

    def authenticate(self) -> None:
        body = urlencode({"grant_type": "client_credentials"}).encode("utf-8")
        basic_credentials = base64.b64encode(
            f"{self.client_id}:{self.client_secret}".encode("utf-8")
        ).decode("ascii")
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": f"Basic {basic_credentials}",
        }
        if self.organization_id:
            headers["X-Umbrella-OrgId"] = self.organization_id
        response = self._request(
            "POST",
            TOKEN_URL,
            body=body,
            headers=headers,
            authenticated=False,
        )
        token = response.get("access_token") if isinstance(response, dict) else None
        if not token:
            raise ImporterError("OAuth token response did not include access_token")
        self.access_token = str(token)

    def list_connector_groups(self) -> list[dict[str, Any]]:
        return self._list("/deployments/v2/connectorGroups")

    def list_private_resources(self) -> list[dict[str, Any]]:
        return self._list("/policies/v2/privateResources")

    def get_connector_group(self, group_id: int) -> dict[str, Any]:
        return self._json("GET", f"/deployments/v2/connectorGroups/{group_id}")

    def get_private_resource(self, resource_id: int) -> dict[str, Any]:
        return self._json("GET", f"/policies/v2/privateResources/{resource_id}")

    def create_private_resource(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._json("POST", "/policies/v2/privateResources", payload)

    def _list(self, path: str) -> list[dict[str, Any]]:
        # Cisco collection APIs return either a bare array or a paginated
        # data/total object. Accept items as a compatibility fallback.
        offset = 0
        collected: list[dict[str, Any]] = []
        while True:
            query = urlencode({"limit": 100, "offset": offset})
            response = self._json("GET", f"{path}?{query}")
            if isinstance(response, list):
                return response
            if not isinstance(response, dict):
                raise ImporterError(f"Unexpected list response from {path}")
            items = response.get("data", response.get("items", []))
            if not isinstance(items, list):
                raise ImporterError(f"Unexpected collection response from {path}")
            collected.extend(item for item in items if isinstance(item, dict))
            total = response.get("total")
            if not items or total is None or len(collected) >= int(total):
                return collected
            offset += len(items)

    def _json(self, method: str, path: str, payload: Any = None) -> Any:
        if not self.access_token:
            raise ImporterError("Authenticate before calling the Cisco API")
        headers = {"Authorization": f"Bearer {self.access_token}"}
        if payload is not None:
            headers["Content-Type"] = "application/json"
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        return self._request(
            method, f"{self.api_root}{path}", body=body, headers=headers, authenticated=True
        )

    def _request(
        self,
        method: str,
        url: str,
        *,
        body: bytes | None,
        headers: dict[str, str],
        authenticated: bool,
    ) -> Any:
        del authenticated  # Documents the two request paths without logging secrets.
        for attempt in range(self.retries + 1):
            request = Request(url, data=body, method=method, headers=headers)
            try:
                with urlopen(request, timeout=30) as response:  # nosec B310: fixed Cisco API URL
                    raw = response.read().decode("utf-8")
                    return json.loads(raw) if raw else {}
            except HTTPError as exc:
                raw = exc.read().decode("utf-8", errors="replace")
                try:
                    parsed: Any = json.loads(raw) if raw else None
                except json.JSONDecodeError:
                    parsed = raw
                retryable = exc.code in {429, 500, 502, 503, 504}
                if retryable and attempt < self.retries:
                    retry_after = exc.headers.get("Retry-After", "")
                    delay = int(retry_after) if retry_after.isdigit() else 2**attempt
                    time.sleep(min(delay, 30))
                    continue
                message = parsed.get("error", raw) if isinstance(parsed, dict) else str(parsed)
                raise ApiError(exc.code, message or exc.reason, parsed) from exc
            except URLError as exc:
                if attempt < self.retries:
                    time.sleep(2**attempt)
                    continue
                raise ImporterError(f"Could not reach Cisco API: {exc.reason}") from exc
        raise AssertionError("unreachable")


class PrivateResourceImporter:
    def __init__(
        self,
        client: CiscoSecureAccessClient,
        dns_server_group: str,
        dns_server_id: int,
    ) -> None:
        self.client = client
        self.dns_server_group = dns_server_group
        self.dns_server_id = dns_server_id

    def preflight(self, items: list[ResourceInput]) -> None:
        private_resources = self.client.list_private_resources()
        if len(private_resources) + len(items) > RESOURCE_LIMIT:
            raise ImporterError(
                "This import would exceed Cisco's 1,000 Private Resource limit"
            )

        existing_names = {
            str(resource.get("name", "")).casefold()
            for resource in private_resources
        }
        conflicts = [item.resource_name for item in items if item.resource_name.casefold() in existing_names]
        if conflicts:
            raise ImporterError(
                "Create-only import refused because these resource names already exist: "
                + ", ".join(conflicts)
            )
        return None

    def run(self, items: list[ResourceInput], apply: bool) -> list[Result]:
        self.preflight(items)
        if not apply:
            return [
                Result(
                    fqdn=item.fqdn,
                    resource_name=item.resource_name,
                    protocol=RDP_PROTOCOL,
                    port=RDP_PORT,
                    dns_server_group=self.dns_server_group,
                    dns_server_id=self.dns_server_id,
                    status="dry-run",
                    message="Validated; no API write was requested",
                )
                for item in items
            ]

        results: list[Result] = []
        for item in items:
            resource_id: int | None = None
            try:
                created = self.client.create_private_resource(
                    build_payload(item, self.dns_server_id)
                )
                resource_id_value = created.get("resourceId")
                if resource_id_value is None:
                    raise ImporterError("Create response did not include resourceId")
                resource_id = int(resource_id_value)

                self._verify_with_retry(resource_id, item)
                results.append(
                    Result(
                        fqdn=item.fqdn,
                        resource_name=item.resource_name,
                        protocol=RDP_PROTOCOL,
                        port=RDP_PORT,
                        dns_server_group=self.dns_server_group,
                        dns_server_id=self.dns_server_id,
                        status="created",
                        resource_id=resource_id,
                    )
                )
            except Exception as exc:
                results.append(
                    Result(
                        fqdn=item.fqdn,
                        resource_name=item.resource_name,
                        protocol=RDP_PROTOCOL,
                        port=RDP_PORT,
                        dns_server_group=self.dns_server_group,
                        dns_server_id=self.dns_server_id,
                        status="failed",
                        resource_id=resource_id,
                        message=str(exc),
                    )
                )
                raise RunFailed(
                    f"Stopped after failure for {item.fqdn}: {exc}", results
                ) from exc
        return results

    def _verify_with_retry(self, resource_id: int, item: ResourceInput) -> None:
        """Allow Cisco's newly-created resource representation to settle."""
        last_error: ImporterError | None = None
        retries = getattr(self.client, "retries", 3)
        for attempt in range(retries + 1):
            try:
                self._verify(resource_id, item)
                return
            except ImporterError as exc:
                last_error = exc
                if attempt < retries:
                    time.sleep(2**attempt)
        assert last_error is not None
        raise last_error

    def _verify(self, resource_id: int, item: ResourceInput) -> None:
        resource = self.client.get_private_resource(resource_id)
        if resource.get("name") != item.resource_name:
            raise ImporterError("Post-create verification returned an unexpected resource name")
        if resource.get("dnsServerId") != self.dns_server_id:
            raise ImporterError("Post-create verification returned an unexpected DNS server")
        client_accesses = [
            access
            for access in resource.get("accessTypes", [])
            if isinstance(access, dict) and access.get("type") == "client"
        ]
        if not any(
            item.fqdn in access.get("reachableAddresses", [])
            for access in client_accesses
        ):
            raise ImporterError("Post-create verification returned unexpected client access")
        protocol_ports = [
            protocol_port
            for address in resource.get("resourceAddresses", [])
            for protocol_port in address.get("protocolPorts", [])
        ]
        if not any(
            str(protocol_port.get("protocol", "")).casefold() == RDP_PROTOCOL.casefold()
            and protocol_port.get("ports") == RDP_PORT
            for protocol_port in protocol_ports
            if isinstance(protocol_port, dict)
        ):
            raise ImporterError("Post-create verification returned an unexpected RDP protocol")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--fqdn", help="One FQDN to create")
    source.add_argument("--csv", type=Path, help="CSV with an fqdn header")
    source.add_argument(
        "--show-connector-group",
        help="Show one Resource Connector Group's configuration; makes no changes",
    )
    source.add_argument(
        "--show-private-resource",
        type=int,
        help="Show one Private Resource's configuration; makes no changes",
    )
    parser.add_argument(
        "--dns-server-group",
        help=(
            "DNS-enabled Resource Connector Group to use; overrides "
            "CISCO_SECURE_ACCESS_DNS_SERVER_GROUP"
        ),
    )
    parser.add_argument(
        "--apply", action="store_true", help="Perform writes; default is dry-run"
    )
    parser.add_argument(
        "--output", type=Path, help="Write JSON results to this file instead of stdout"
    )
    args = parser.parse_args(argv)
    return args


def load_inputs(args: argparse.Namespace) -> list[ResourceInput]:
    if args.csv:
        return parse_csv(args.csv)
    return validate_inputs(
        [
            ResourceInput(normalise_fqdn(args.fqdn), 1)
        ]
    )


def emit_results(results: list[Result], output: Path | None) -> None:
    emit_json([asdict(result) for result in results], output)


def emit_json(data: Any, output: Path | None) -> None:
    text = json.dumps(data, indent=2) + "\n"
    if output:
        output.write_text(text, encoding="utf-8")
        print(f"Wrote results to {output}")
    else:
        print(text, end="")


def connector_group_details(client: CiscoSecureAccessClient, name: str) -> dict[str, Any]:
    matches = [
        group
        for group in client.list_connector_groups()
        if str(group.get("name", "")).casefold() == name.casefold()
    ]
    if len(matches) != 1 or "id" not in matches[0]:
        raise ImporterError(
            f"Connector Group {name!r} did not resolve to exactly one group"
        )
    group = client.get_connector_group(int(matches[0]["id"]))
    return {
        field: group.get(field)
        for field in (
            "id",
            "name",
            "location",
            "environment",
            "status",
            "connectorsCount",
            "connectedConnectorsCount",
            "resourceIds",
            "forwardDNS",
        )
    }


def private_resource_details(
    client: CiscoSecureAccessClient, resource_id: int
) -> dict[str, Any]:
    resource = client.get_private_resource(resource_id)
    return {
        field: resource.get(field)
        for field in (
            "resourceId",
            "name",
            "description",
            "dnsServerId",
            "accessTypes",
            "resourceAddresses",
            "resourceGroupIds",
            "createdAt",
            "modifiedAt",
        )
    }


def resolve_dns_server_group(client: CiscoSecureAccessClient, name: str) -> int:
    """Resolve a DNS-enabled Connector Group name to Cisco's DNS server ID."""
    matches = [
        group
        for group in client.list_connector_groups()
        if str(group.get("name", "")).casefold() == name.casefold()
    ]
    if len(matches) != 1 or "id" not in matches[0]:
        raise ImporterError(
            f"DNS server group {name!r} did not resolve to exactly one Connector Group"
        )
    group = client.get_connector_group(int(matches[0]["id"]))
    forward_dns = group.get("forwardDNS") or []
    if isinstance(forward_dns, dict):
        forward_dns = [forward_dns]
    dns_server_ids = {
        int(entry["dnsResourceId"])
        for entry in forward_dns
        if isinstance(entry, dict) and entry.get("dnsResourceId") is not None
    }
    if len(dns_server_ids) != 1:
        raise ImporterError(
            f"DNS server group {name!r} must expose exactly one forwardDNS dnsResourceId; "
            f"found {len(dns_server_ids)}"
        )
    return dns_server_ids.pop()


def discover_dns_server_choices(client: CiscoSecureAccessClient) -> list[DnsServerChoice]:
    """Return every DNS server exposed by a Connector Group's forward DNS."""
    choices: list[DnsServerChoice] = []
    for listed_group in client.list_connector_groups():
        if "id" not in listed_group:
            continue
        group_id = int(listed_group["id"])
        group_name = str(listed_group.get("name", group_id))
        group = client.get_connector_group(group_id)
        forward_dns = group.get("forwardDNS") or []
        if isinstance(forward_dns, dict):
            forward_dns = [forward_dns]
        for entry in forward_dns:
            if not isinstance(entry, dict) or entry.get("dnsResourceId") is None:
                continue
            domains_value = entry.get("domains")
            if isinstance(domains_value, list):
                domains = ", ".join(str(domain) for domain in domains_value)
            else:
                domains = str(domains_value or "all domains")
            choices.append(
                DnsServerChoice(
                    connector_group_name=group_name,
                    connector_group_id=group_id,
                    dns_server_id=int(entry["dnsResourceId"]),
                    domains=domains,
                )
            )
    return sorted(
        choices,
        key=lambda choice: (
            choice.connector_group_name.casefold(),
            choice.connector_group_id,
            choice.dns_server_id,
        ),
    )


def prompt_for_dns_server_choice(
    choices: list[DnsServerChoice],
) -> DnsServerChoice:
    if not choices:
        raise ImporterError(
            "No DNS-enabled Connector Groups with a forwardDNS dnsResourceId were found"
        )
    print("Available internal DNS servers:", file=sys.stderr)
    for index, choice in enumerate(choices, start=1):
        print(
            f"  {index}. {choice.connector_group_name} "
            f"(Connector Group {choice.connector_group_id}; "
            f"DNS server {choice.dns_server_id}; domains: {choice.domains})",
            file=sys.stderr,
        )
    while True:
        print(
            f"Select an internal DNS server [1-{len(choices)}] (or q to cancel): ",
            end="",
            file=sys.stderr,
            flush=True,
        )
        selection = sys.stdin.readline()
        if not selection:
            raise ImporterError("Interactive DNS selection was cancelled")
        selection = selection.strip()
        if selection.casefold() in {"q", "quit"}:
            raise ImporterError("Interactive DNS selection was cancelled")
        if selection.isdigit() and 1 <= int(selection) <= len(choices):
            return choices[int(selection) - 1]
        print("Enter one of the displayed numbers, or q to cancel.", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    try:
        args = parse_args(argv)
        client = CiscoSecureAccessClient.from_environment()
        client.authenticate()
        if args.show_connector_group:
            emit_json(
                connector_group_details(client, args.show_connector_group), args.output
            )
            return 0
        if args.show_private_resource:
            emit_json(
                private_resource_details(client, args.show_private_resource), args.output
            )
            return 0
        items = load_inputs(args)
        dns_server_group = args.dns_server_group or os.getenv(
            "CISCO_SECURE_ACCESS_DNS_SERVER_GROUP"
        )
        if dns_server_group:
            dns_server_id = resolve_dns_server_group(client, dns_server_group)
        else:
            if not sys.stdin.isatty():
                raise ImporterError(
                    "Set CISCO_SECURE_ACCESS_DNS_SERVER_GROUP or pass "
                    "--dns-server-group when standard input is not interactive"
                )
            choice = prompt_for_dns_server_choice(discover_dns_server_choices(client))
            dns_server_group = choice.connector_group_name
            dns_server_id = choice.dns_server_id
        importer = PrivateResourceImporter(client, dns_server_group, dns_server_id)
        results = importer.run(items, args.apply)
        emit_results(results, args.output)
        return 0
    except RunFailed as exc:
        emit_results(exc.results, args.output if "args" in locals() else None)
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except ImporterError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
