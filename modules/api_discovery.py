"""API schema discovery module.

Discovers OpenAPI/Swagger specs, extracts API endpoints from JavaScript,
and (Task 15) probes GraphQL introspection. Passive/read-only — no
--confirm needed.
"""

from __future__ import annotations

import argparse
import json
import logging
import pathlib
import re
import sys
from typing import Any
from urllib.parse import urljoin, urlparse

from modules.common import (
    make_alert,
    get_session,
    audit_log,
    print_dry_run,
    fetch_page,
    parse_html,
    is_same_origin,
    resolve_url,
    load_lines,
    extract_script_sources,
)

logger = logging.getLogger("dora_modules.api_discovery")

_PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
_API_SPEC_PATHS_FILE = _PROJECT_ROOT / "wordlists" / "api_spec_paths.txt"
_GRAPHQL_PATHS_FILE = _PROJECT_ROOT / "wordlists" / "graphql_paths.txt"

_JS_ENDPOINT_RE = re.compile(
    r"""(?:["'])(\/api\/[a-zA-Z0-9_\-\/\{\}:.]+)(?:["'])""",
)
_MAX_JS_SCRIPTS = 25

_GRAPHQL_INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields {
        name
      }
    }
  }
}
""".strip()


# ---------------------------------------------------------------------------
# OpenAPI / Swagger discovery
# ---------------------------------------------------------------------------

def discover_openapi_spec(
    session: Any, target: str, timeout: int = 15,
) -> tuple[dict | None, str]:
    """Probe common spec paths. Returns (spec_dict, url) or (None, '')."""
    spec_paths = load_lines(_API_SPEC_PATHS_FILE)
    if not spec_paths:
        spec_paths = ["/swagger.json", "/openapi.json", "/api-docs"]

    for path in spec_paths:
        url = urljoin(target.rstrip("/") + "/", path.lstrip("/"))
        resp, err = fetch_page(session, url, timeout=timeout)
        if resp is None or resp.status_code != 200:
            continue

        content_type = resp.headers.get("content-type", "")
        if "json" not in content_type and "yaml" not in content_type:
            if not resp.text.strip().startswith(("{", "openapi", "swagger")):
                continue

        try:
            spec = json.loads(resp.text)
        except json.JSONDecodeError:
            try:
                import yaml
                spec = yaml.safe_load(resp.text)
            except Exception:
                continue

        if not isinstance(spec, dict):
            continue
        if "swagger" in spec or "openapi" in spec or "paths" in spec:
            return spec, url

    return None, ""


def parse_openapi_endpoints(spec: dict) -> list[dict[str, Any]]:
    """Walk OpenAPI 3.x / Swagger 2.0 spec and extract endpoints."""
    endpoints: list[dict[str, Any]] = []
    paths = spec.get("paths", {})
    if not isinstance(paths, dict):
        return endpoints

    for path, methods_obj in paths.items():
        if not isinstance(methods_obj, dict):
            continue
        for method, details in methods_obj.items():
            method_upper = method.upper()
            if method_upper not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
                continue
            summary = ""
            if isinstance(details, dict):
                summary = details.get("summary", "") or details.get("operationId", "")
            endpoints.append({
                "path": path,
                "method": method_upper,
                "summary": str(summary),
                "auth_required": _endpoint_requires_auth(details),
            })

    return endpoints


def _endpoint_requires_auth(details: Any) -> bool:
    if not isinstance(details, dict):
        return False
    if details.get("security"):
        return True
    return False


# ---------------------------------------------------------------------------
# JS endpoint extraction
# ---------------------------------------------------------------------------

def discover_endpoints_from_js(
    session: Any, target: str, html: str, timeout: int = 15,
) -> list[str]:
    """Extract /api/... path literals from same-origin JavaScript files."""
    resources = extract_script_sources(html, target)
    same_origin_scripts = [
        r for r in resources
        if r["tag"] == "script" and is_same_origin(target, r["src"])
    ][:_MAX_JS_SCRIPTS]

    found: set[str] = set()
    for resource in same_origin_scripts:
        resp, err = fetch_page(session, resource["src"], timeout=timeout)
        if resp is None or resp.status_code != 200:
            continue
        for match in _JS_ENDPOINT_RE.findall(resp.text):
            found.add(match)

    return sorted(found)


# ---------------------------------------------------------------------------
# GraphQL introspection
# ---------------------------------------------------------------------------

def test_graphql_introspection(
    session: Any, target: str, timeout: int = 15,
) -> list[dict[str, Any]]:
    """Probe common GraphQL endpoints with an introspection query."""
    alerts: list[dict[str, Any]] = []
    graphql_paths = load_lines(_GRAPHQL_PATHS_FILE)
    if not graphql_paths:
        graphql_paths = ["/graphql", "/api/graphql"]

    for path in graphql_paths:
        url = urljoin(target.rstrip("/") + "/", path.lstrip("/"))
        try:
            resp = session.post(
                url,
                json={"query": _GRAPHQL_INTROSPECTION_QUERY},
                timeout=timeout,
                headers={"Content-Type": "application/json"},
            )
        except Exception:
            continue

        if resp.status_code != 200:
            continue

        try:
            data = resp.json()
        except Exception:
            continue

        schema = data.get("data", {})
        if not isinstance(schema, dict):
            continue
        schema_obj = schema.get("__schema")
        if not isinstance(schema_obj, dict):
            continue

        types = schema_obj.get("types", [])
        type_names = [t.get("name", "") for t in types if isinstance(t, dict)]
        user_types = [n for n in type_names if not n.startswith("__")]

        has_mutations = schema_obj.get("mutationType") is not None
        mutation_type_name = ""
        if has_mutations and isinstance(schema_obj["mutationType"], dict):
            mutation_type_name = schema_obj["mutationType"].get("name", "")

        mutation_fields: list[str] = []
        if mutation_type_name:
            for t in types:
                if isinstance(t, dict) and t.get("name") == mutation_type_name:
                    for f in t.get("fields", []) or []:
                        if isinstance(f, dict):
                            mutation_fields.append(f.get("name", ""))
                    break

        risk = "High" if has_mutations else "Medium"
        mutation_info = ""
        if has_mutations:
            mutation_info = (
                f" The schema exposes {len(mutation_fields)} mutation(s)"
                f"{': ' + ', '.join(mutation_fields[:10]) if mutation_fields else ''}."
                f" Mutations allow state-changing operations."
            )

        alerts.append(make_alert(
            risk=risk,
            alert_name="GraphQL Introspection Enabled",
            url=url,
            description=(
                f"GraphQL introspection is enabled at {url}. "
                f"The schema exposes {len(user_types)} user-defined type(s)."
                f"{mutation_info}"
            ),
            solution=(
                "Disable GraphQL introspection in production. "
                "If mutations are exposed, ensure proper authentication "
                "and authorization on all mutation resolvers."
            ),
            cweid="200",
            evidence=f"Types: {', '.join(user_types[:15])}",
        ))
        break  # Found a working endpoint, stop probing

    return alerts


# ---------------------------------------------------------------------------
# Public entry point for cross-module reuse
# ---------------------------------------------------------------------------

def get_discovered_endpoints(
    target: str,
    *,
    timeout: int = 15,
    session_override: Any | None = None,
) -> list[dict[str, Any]]:
    """Return combined list of discovered endpoints for other modules to use."""
    session = session_override or get_session(timeout=timeout)
    all_endpoints: list[dict[str, Any]] = []

    # OpenAPI
    spec, spec_url = discover_openapi_spec(session, target, timeout=timeout)
    if spec:
        openapi_eps = parse_openapi_endpoints(spec)
        for ep in openapi_eps:
            ep["source"] = "openapi"
            ep["spec_url"] = spec_url
        all_endpoints.extend(openapi_eps)

    # JS extraction
    resp, _ = fetch_page(session, target, timeout=timeout)
    if resp and resp.status_code == 200:
        js_paths = discover_endpoints_from_js(session, target, resp.text, timeout=timeout)
        for path in js_paths:
            all_endpoints.append({
                "path": path,
                "method": "UNKNOWN",
                "summary": "",
                "source": "javascript",
                "auth_required": False,
            })

    return all_endpoints


# ---------------------------------------------------------------------------
# run_scan
# ---------------------------------------------------------------------------

def run_scan(
    target: str,
    *,
    timeout: int = 15,
    dry_run: bool = False,
    session_override: Any | None = None,
) -> list[dict[str, Any]]:
    """Discover API specs/endpoints and return alerts."""
    target = target.rstrip("/")
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    checks = [
        "OpenAPI/Swagger spec discovery",
        "API endpoint extraction from JavaScript",
        "GraphQL introspection probe",
    ]

    if dry_run:
        print_dry_run("api_discovery", target, checks)
        return []

    audit_log("API_DISCOVERY_START", target, "api_discovery")
    session = session_override or get_session(timeout=timeout)
    alerts: list[dict[str, Any]] = []

    # OpenAPI spec discovery
    print("  [1/3] Probing for OpenAPI/Swagger specifications ...")
    spec, spec_url = discover_openapi_spec(session, target, timeout=timeout)
    if spec:
        endpoints = parse_openapi_endpoints(spec)
        version = spec.get("openapi", spec.get("swagger", "unknown"))
        info_title = spec.get("info", {}).get("title", "unknown") if isinstance(spec.get("info"), dict) else "unknown"

        alerts.append(make_alert(
            risk="Medium",
            alert_name="OpenAPI/Swagger Specification Publicly Accessible",
            url=spec_url,
            description=(
                f"An OpenAPI/Swagger specification (version {version}, "
                f"title: '{info_title}') was found at {spec_url}. "
                f"It exposes {len(endpoints)} endpoint(s). "
                f"This reveals the full API surface to attackers."
            ),
            solution=(
                "Restrict access to API documentation in production. "
                "If intentionally public, ensure all listed endpoints "
                "have proper authentication and authorization."
            ),
            cweid="200",
            evidence=f"Spec version: {version}, endpoints: {len(endpoints)}",
        ))

        # Check for unauthenticated endpoints
        unauth = [e for e in endpoints if not e["auth_required"]]
        if unauth:
            paths_str = ", ".join(e["path"] for e in unauth[:10])
            extra = f" ... and {len(unauth) - 10} more" if len(unauth) > 10 else ""
            alerts.append(make_alert(
                risk="Low",
                alert_name="API Endpoints Without Authentication Requirement",
                url=spec_url,
                description=(
                    f"{len(unauth)} endpoint(s) in the OpenAPI spec do not "
                    f"declare a security requirement: {paths_str}{extra}"
                ),
                solution="Review and add security requirements to all API endpoints.",
                evidence=paths_str,
            ))
        print(f"        Found spec at {spec_url} with {len(endpoints)} endpoint(s)")
    else:
        print("        No OpenAPI/Swagger spec found")

    # JS endpoint extraction
    print("  [2/3] Extracting API endpoints from JavaScript ...")
    resp, _ = fetch_page(session, target, timeout=timeout)
    js_endpoints: list[str] = []
    if resp and resp.status_code == 200:
        js_endpoints = discover_endpoints_from_js(session, target, resp.text, timeout=timeout)

    if js_endpoints:
        paths_str = "\n".join(js_endpoints[:20])
        extra = f"\n... and {len(js_endpoints) - 20} more" if len(js_endpoints) > 20 else ""
        alerts.append(make_alert(
            risk="Informational",
            alert_name="API Endpoints Discovered in JavaScript",
            url=target,
            description=(
                f"Found {len(js_endpoints)} API endpoint path(s) referenced "
                f"in client-side JavaScript files."
            ),
            solution="Ensure all discovered endpoints have proper authentication and authorization.",
            evidence=f"{paths_str}{extra}",
        ))
        print(f"        Found {len(js_endpoints)} endpoint(s) in JavaScript")
    else:
        print("        No API endpoints found in JavaScript")

    # GraphQL introspection
    print("  [3/3] Probing for GraphQL introspection ...")
    gql_alerts = test_graphql_introspection(session, target, timeout=timeout)
    alerts.extend(gql_alerts)
    if gql_alerts:
        print(f"        GraphQL introspection enabled ({len(gql_alerts)} alert(s))")
    else:
        print("        No GraphQL endpoint found or introspection disabled")

    audit_log(
        "API_DISCOVERY_COMPLETE", target, "api_discovery",
        extra=f"alerts={len(alerts)}",
    )
    return alerts


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="api_discovery",
        description="API schema discovery for DORA Article 24 assessments.",
    )
    p.add_argument("--target", required=True, help="Target URL")
    p.add_argument("--timeout", type=int, default=15, help="HTTP timeout (default: 15)")
    p.add_argument("--dry-run", action="store_true", help="Print plan without executing")
    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    alerts = run_scan(args.target, timeout=args.timeout, dry_run=args.dry_run)

    if alerts:
        print(f"\n{'='*60}")
        print(f"  {len(alerts)} alert(s) generated")
        print(f"{'='*60}")
        for a in alerts:
            print(f"  [{a['risk']}] {a['alert']}")
    else:
        print("\n[api_discovery] No alerts generated.")


if __name__ == "__main__":
    main()
