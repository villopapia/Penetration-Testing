"""Module 2 -- Supply-chain / dependency checker (passive, GET-only).

Discovers JavaScript libraries loaded by the target, checks them for
known CVEs via OSV.dev, validates Subresource Integrity (SRI) on
cross-origin resources, and optionally probes for exposed package
manifests.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import logging
import pathlib
import re
import sys
import time
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

# ---------------------------------------------------------------------------
# Ensure the project root is importable
# ---------------------------------------------------------------------------
_PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from modules.common import (
    audit_log,
    fetch_page,
    get_session,
    is_same_origin,
    make_alert,
    parse_html,
    print_dry_run,
    resolve_url,
)

logger = logging.getLogger("dora_modules.supply_chain")

DATA_DIR = _PROJECT_ROOT / "data"
SIGNATURES_PATH = DATA_DIR / "js_library_signatures.json"
CVE_CACHE_PATH = DATA_DIR / "cve_feed_cache.json"

OSV_API_URL = "https://api.osv.dev/v1/query"
CVE_CACHE_TTL_DAYS = 7

# Max bytes to fetch from a local script to look for version comments
_LOCAL_SCRIPT_HEAD_BYTES = 4096

# CDN host fragments used to recognise third-party script sources
_CDN_HOSTS = (
    "cdnjs.cloudflare.com",
    "cdn.jsdelivr.net",
    "unpkg.com",
    "code.jquery.com",
    "ajax.googleapis.com",
    "stackpath.bootstrapcdn.com",
    "cdn.datatables.net",
    "cdn.socket.io",
    "d3js.org",
    "maxcdn.bootstrapcdn.com",
)

# Manifest paths to probe when check_manifests=True
_MANIFEST_PATHS = (
    "/package.json",
    "/composer.json",
    "/requirements.txt",
    "/.git/config",
    "/.env",
    "/Gemfile",
)

# CVSS-to-risk mapping thresholds
_CVSS_RISK = [
    (9.0, "Critical"),
    (7.0, "High"),
    (4.0, "Medium"),
    (0.1, "Low"),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_signatures() -> dict[str, Any]:
    with open(SIGNATURES_PATH, encoding="utf-8") as f:
        return json.load(f)


def _cvss_to_risk(score: float) -> str:
    for threshold, label in _CVSS_RISK:
        if score >= threshold:
            return label
    return "Informational"


# ---------------------------------------------------------------------------
# CVE cache
# ---------------------------------------------------------------------------

def _load_cve_cache() -> dict[str, Any]:
    if not CVE_CACHE_PATH.exists():
        return {}
    try:
        with open(CVE_CACHE_PATH, encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _save_cve_cache(cache: dict[str, Any]) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with open(CVE_CACHE_PATH, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2, default=str)


def _cache_key(package: str, version: str) -> str:
    return f"{package}@{version}"


def _is_cache_fresh(entry: dict[str, Any]) -> bool:
    try:
        cached_at = dt.datetime.fromisoformat(entry["cached_at"])
        return (dt.datetime.now(dt.timezone.utc) - cached_at).days < CVE_CACHE_TTL_DAYS
    except (KeyError, ValueError):
        return False


# ---------------------------------------------------------------------------
# 1. JS Library Discovery
# ---------------------------------------------------------------------------

def _extract_script_sources(html: str, base_url: str) -> list[dict[str, Any]]:
    """Parse <script src> and <link href> tags, returning structured info."""
    soup = parse_html(html)
    resources: list[dict[str, Any]] = []

    for tag in soup.find_all("script", src=True):
        src = tag["src"]
        absolute = resolve_url(base_url, src)
        resources.append({
            "tag": "script",
            "src": absolute,
            "raw_src": src,
            "integrity": tag.get("integrity", ""),
            "crossorigin": tag.get("crossorigin", ""),
        })

    for tag in soup.find_all("link", href=True):
        rel = " ".join(tag.get("rel", []))
        if "stylesheet" in rel:
            href = tag["href"]
            absolute = resolve_url(base_url, href)
            resources.append({
                "tag": "link",
                "src": absolute,
                "raw_src": href,
                "integrity": tag.get("integrity", ""),
                "crossorigin": tag.get("crossorigin", ""),
            })

    return resources


def _identify_from_url(src: str, signatures: dict[str, Any]) -> tuple[str, str] | None:
    """Try to identify library + version from the URL alone using CDN patterns."""
    for lib_name, sig in signatures.items():
        for pattern in sig.get("cdn_patterns", []):
            m = re.search(pattern, src, re.IGNORECASE)
            if m and m.group(1):
                return lib_name, m.group(1)
    return None


def _identify_from_content(
    content: str, signatures: dict[str, Any]
) -> tuple[str, str] | None:
    """Try to identify library + version from script content using inline patterns."""
    for lib_name, sig in signatures.items():
        for pattern in sig.get("inline_patterns", []):
            m = re.search(pattern, content)
            if m:
                try:
                    version = m.group(1)
                    return lib_name, version
                except IndexError:
                    continue
    return None


def discover_libraries(
    session: requests.Session,
    base_url: str,
    html: str,
    signatures: dict[str, Any],
    timeout: int = 15,
) -> list[dict[str, Any]]:
    """Discover JS libraries: returns list of {name, version, src, method}."""
    resources = _extract_script_sources(html, base_url)
    found: list[dict[str, Any]] = []
    seen: set[str] = set()

    for res in resources:
        if res["tag"] != "script":
            continue

        src = res["src"]

        # Try URL-based identification first
        ident = _identify_from_url(src, signatures)
        if ident:
            key = f"{ident[0]}@{ident[1]}"
            if key not in seen:
                seen.add(key)
                found.append({
                    "name": ident[0],
                    "version": ident[1],
                    "src": src,
                    "method": "cdn_url",
                    "package_name": signatures[ident[0]].get("package_name", ident[0].lower()),
                    "ecosystem": signatures[ident[0]].get("ecosystem", "npm"),
                })
            continue

        # For local/same-origin scripts, fetch the first few KB and inspect
        if is_same_origin(base_url, src):
            try:
                resp = session.get(
                    src,
                    timeout=timeout,
                    headers={"Range": f"bytes=0-{_LOCAL_SCRIPT_HEAD_BYTES}"},
                    allow_redirects=True,
                )
                if resp.status_code in (200, 206):
                    ident = _identify_from_content(resp.text, signatures)
                    if ident:
                        key = f"{ident[0]}@{ident[1]}"
                        if key not in seen:
                            seen.add(key)
                            found.append({
                                "name": ident[0],
                                "version": ident[1],
                                "src": src,
                                "method": "inline_comment",
                                "package_name": signatures[ident[0]].get("package_name", ident[0].lower()),
                                "ecosystem": signatures[ident[0]].get("ecosystem", "npm"),
                            })
            except requests.RequestException:
                pass

    return found


# ---------------------------------------------------------------------------
# 2. CVE Lookup via OSV.dev
# ---------------------------------------------------------------------------

def lookup_cves(
    session: requests.Session,
    package_name: str,
    version: str,
    ecosystem: str = "npm",
) -> list[dict[str, Any]]:
    """Query OSV.dev for known vulnerabilities. Returns list of vuln dicts."""
    cache = _load_cve_cache()
    key = _cache_key(package_name, version)

    if key in cache and _is_cache_fresh(cache[key]):
        return cache[key].get("vulns", [])

    payload = {
        "package": {"name": package_name, "ecosystem": ecosystem},
        "version": version,
    }

    try:
        resp = session.post(OSV_API_URL, json=payload, timeout=20)
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as e:
        logger.warning("OSV.dev query failed for %s@%s: %s", package_name, version, e)
        return []
    except (json.JSONDecodeError, ValueError):
        logger.warning("OSV.dev returned invalid JSON for %s@%s", package_name, version)
        return []

    vulns = data.get("vulns", [])

    # Normalize into a simpler structure
    results: list[dict[str, Any]] = []
    for v in vulns:
        severity_score = 0.0
        for sev in v.get("severity", []):
            try:
                severity_score = max(severity_score, float(sev.get("score", 0)))
            except (ValueError, TypeError):
                pass

        # Some OSV entries carry CVSS in database_specific or via severity
        if severity_score == 0.0:
            for sev in v.get("severity", []):
                score_str = sev.get("score", "")
                if isinstance(score_str, str) and score_str:
                    try:
                        severity_score = float(score_str)
                    except ValueError:
                        pass

        aliases = v.get("aliases", [])
        cve_id = next((a for a in aliases if a.startswith("CVE-")), "")

        results.append({
            "id": v.get("id", ""),
            "cve": cve_id,
            "summary": v.get("summary", v.get("details", "")[:200]),
            "severity_score": severity_score,
            "risk": _cvss_to_risk(severity_score) if severity_score > 0 else "Medium",
            "aliases": aliases,
            "references": [
                ref.get("url", "") for ref in v.get("references", []) if ref.get("url")
            ][:3],
        })

    # Update cache
    cache[key] = {
        "cached_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "vulns": results,
    }
    _save_cve_cache(cache)

    return results


# ---------------------------------------------------------------------------
# 3. SRI Check
# ---------------------------------------------------------------------------

def check_sri(resources: list[dict[str, Any]], base_url: str) -> list[dict[str, Any]]:
    """Check cross-origin <script>/<link> tags for missing integrity attributes."""
    missing: list[dict[str, Any]] = []
    for res in resources:
        if is_same_origin(base_url, res["src"]):
            continue
        if not res.get("integrity"):
            missing.append(res)
    return missing


# ---------------------------------------------------------------------------
# 4. Exposed Package Manifests
# ---------------------------------------------------------------------------

def check_manifests(
    session: requests.Session, base_url: str, timeout: int = 10
) -> list[dict[str, Any]]:
    """Probe for publicly accessible package manifests and config files."""
    exposed: list[dict[str, Any]] = []
    for path in _MANIFEST_PATHS:
        url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        try:
            resp = session.get(url, timeout=timeout, allow_redirects=False)
            if resp.status_code == 200 and len(resp.text.strip()) > 2:
                # Extra validation: make sure we didn't get a generic HTML error page
                content_type = resp.headers.get("content-type", "")
                if "html" not in content_type.lower() or path.endswith(".html"):
                    exposed.append({
                        "path": path,
                        "url": url,
                        "size": len(resp.content),
                        "content_type": content_type,
                    })
                elif path in ("/package.json", "/composer.json"):
                    # JSON files served as text/html may still be actual JSON
                    try:
                        json.loads(resp.text)
                        exposed.append({
                            "path": path,
                            "url": url,
                            "size": len(resp.content),
                            "content_type": content_type,
                        })
                    except json.JSONDecodeError:
                        pass
        except requests.RequestException:
            pass
    return exposed


# ---------------------------------------------------------------------------
# Main scan entry point
# ---------------------------------------------------------------------------

def run_scan(
    target: str,
    *,
    dry_run: bool = False,
    check_manifests_flag: bool = False,
    timeout: int = 15,
    verify_tls: bool = True,
) -> list[dict[str, Any]]:
    """Run the supply-chain checker against *target*.

    Returns a list of alert dicts compatible with zap_scan._parse_alerts.
    """
    checks = [
        "JS library discovery via <script> tag analysis",
        "CVE lookup for discovered libraries via OSV.dev",
        "Subresource Integrity (SRI) validation on cross-origin resources",
    ]
    if check_manifests_flag:
        checks.append("Exposed package manifest probing")

    if dry_run:
        print_dry_run(
            "Supply-Chain Checker",
            target,
            checks,
            check_manifests=check_manifests_flag,
        )
        return []

    audit_log("START", target, "supply_chain")
    alerts: list[dict[str, Any]] = []
    session = get_session(timeout=timeout, verify_tls=verify_tls)

    # -- Fetch the target page --
    resp, err = fetch_page(session, target, timeout=timeout)
    if resp is None:
        logger.error("Failed to fetch target %s: %s", target, err)
        audit_log("ERROR", target, "supply_chain", extra=f"fetch_failed: {err}")
        return []

    html = resp.text
    signatures = _load_signatures()

    # -- 1. Discover libraries --
    libraries = discover_libraries(session, target, html, signatures, timeout=timeout)
    logger.info("Discovered %d JS libraries on %s", len(libraries), target)

    # -- 2. CVE lookup for each library --
    for lib in libraries:
        vulns = lookup_cves(
            session,
            lib["package_name"],
            lib["version"],
            lib.get("ecosystem", "npm"),
        )
        if vulns:
            for vuln in vulns:
                ref_links = "\n".join(vuln.get("references", []))
                alerts.append(make_alert(
                    risk=vuln["risk"],
                    alert_name=f"Vulnerable JS Library: {lib['name']} {lib['version']}",
                    url=lib["src"],
                    description=(
                        f"{lib['name']} version {lib['version']} has a known vulnerability "
                        f"({vuln.get('cve') or vuln.get('id', 'unknown')}). "
                        f"{vuln.get('summary', '')}"
                    ),
                    solution=(
                        f"Update {lib['name']} to the latest patched version. "
                        f"Review the vulnerability details and assess impact on "
                        f"the application."
                    ),
                    cweid="1035",
                    reference=ref_links,
                    evidence=f"{vuln.get('cve') or vuln.get('id', '')}",
                ))
        else:
            # No known vulns -- still note the library was detected
            alerts.append(make_alert(
                risk="Informational",
                alert_name=f"JS Library Detected: {lib['name']} {lib['version']}",
                url=lib["src"],
                description=(
                    f"Detected {lib['name']} version {lib['version']} loaded via "
                    f"{lib['method']}. No known vulnerabilities found in OSV.dev."
                ),
                solution="Keep the library updated and monitor for future advisories.",
                cweid="1035",
            ))

    # -- 3. SRI check --
    resources = _extract_script_sources(html, target)
    missing_sri = check_sri(resources, target)
    for res in missing_sri:
        alerts.append(make_alert(
            risk="Medium",
            alert_name="Missing Subresource Integrity (SRI)",
            url=res["src"],
            description=(
                f"The cross-origin {res['tag']} resource loaded from {res['src']} "
                f"does not include an integrity attribute. Without SRI, a compromise "
                f"of the CDN or third-party host could inject malicious code into "
                f"the application."
            ),
            solution=(
                "Add an integrity attribute with a cryptographic hash (SHA-256, "
                "SHA-384, or SHA-512) and a crossorigin attribute to all "
                "cross-origin script and stylesheet tags."
            ),
            cweid="829",
            wascid="15",
            reference="https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity",
        ))

    # -- 4. Manifest probing (optional) --
    if check_manifests_flag:
        exposed = check_manifests(session, target, timeout=timeout)
        for manifest in exposed:
            risk = "High" if manifest["path"] in ("/.git/config", "/.env") else "Medium"
            alerts.append(make_alert(
                risk=risk,
                alert_name=f"Exposed Package Manifest: {manifest['path']}",
                url=manifest["url"],
                description=(
                    f"The file {manifest['path']} is publicly accessible "
                    f"({manifest['size']} bytes, Content-Type: {manifest['content_type']}). "
                    f"This may reveal internal dependencies, versions, or configuration "
                    f"details that aid further attacks."
                ),
                solution=(
                    "Restrict access to package manifests and configuration files. "
                    "Configure the web server to deny requests to these paths, or "
                    "remove them from the web root."
                ),
                cweid="538",
                wascid="13",
            ))

    audit_log(
        "COMPLETE",
        target,
        "supply_chain",
        extra=f"alerts={len(alerts)} libraries={len(libraries)}",
    )
    return alerts


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="supply_chain",
        description=(
            "Supply-chain dependency checker -- discovers JS libraries, "
            "looks up CVEs, validates SRI, and probes for exposed manifests."
        ),
    )
    p.add_argument(
        "--target",
        required=True,
        help="Full URL to check, e.g. https://staging.example.com",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would happen without making any requests",
    )
    p.add_argument(
        "--check-manifests",
        action="store_true",
        help="Probe for exposed package manifests (/package.json, /.git/config, etc.)",
    )
    p.add_argument(
        "--timeout",
        type=int,
        default=15,
        help="HTTP request timeout in seconds (default: 15)",
    )
    p.add_argument(
        "--no-verify-tls",
        action="store_true",
        help="Disable TLS certificate verification",
    )
    p.add_argument(
        "--output",
        type=pathlib.Path,
        default=None,
        help="Write JSON alerts to this file",
    )
    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    alerts = run_scan(
        args.target,
        dry_run=args.dry_run,
        check_manifests_flag=args.check_manifests,
        timeout=args.timeout,
        verify_tls=not args.no_verify_tls,
    )

    if not alerts:
        print("\nNo findings.")
        return

    # Summary
    severity_counts: dict[str, int] = {}
    for a in alerts:
        sev = a.get("risk", "Informational")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    print(f"\n{'=' * 60}")
    print(f"  Supply-Chain Check Complete: {len(alerts)} finding(s)")
    print(f"{'=' * 60}")
    for sev in ("Critical", "High", "Medium", "Low", "Informational"):
        count = severity_counts.get(sev, 0)
        if count:
            print(f"  {sev}: {count}")
    print()

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(alerts, f, indent=2, default=str)
        print(f"Alerts written to {args.output}")
    else:
        for a in alerts:
            print(f"  [{a['risk']}] {a['alert']}")
            print(f"    URL: {a['url']}")
            print()


if __name__ == "__main__":
    main()
