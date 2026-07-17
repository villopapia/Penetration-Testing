"""Ransomware readiness assessment module.

Assesses an organisation's web-facing exposure to ransomware attack vectors
by combining passive web checks with optional network port scanning.

Designed for CySEC ICT regulators performing assessments under DORA Article 24.
"""

from __future__ import annotations

import argparse
import re
import socket
import sys
from typing import Any
from urllib.parse import urlparse

from modules.common import (
    make_alert,
    get_session,
    interactive_confirm,
    audit_log,
    print_dry_run,
    fetch_page,
    parse_html,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ADMIN_PATHS: list[str] = [
    "/admin",
    "/admin/",
    "/admin/login",
    "/administrator",
    "/administrator/login",
    "/wp-admin",
    "/wp-login.php",
    "/manager/html",
    "/phpmyadmin",
    "/cpanel",
    "/webmail",
    "/dashboard",
    "/console",
    "/adminer",
    "/solr",
    "/jenkins",
    "/grafana",
    "/kibana",
    "/portainer",
    "/traefik",
    "/admin/dashboard",
    "/panel",
    "/controlpanel",
    "/login",
    "/user/login",
    "/cms",
    "/cms/admin",
    "/siteadmin",
    "/webadmin",
    "/admin.php",
    "/jmx-console",
    "/manager",
    "/manage",
    "/server-status",
    "/server-info",
    "/_admin",
    "/admin_area",
    "/wp-admin/install.php",
]

ADMIN_KEYWORDS: list[str] = [
    "login",
    "sign in",
    "signin",
    "log in",
    "username",
    "password",
    "admin",
    "dashboard",
    "control panel",
    "management console",
    "administrator",
    "authentication",
]

ADMIN_TITLE_KEYWORDS: list[str] = [
    "admin",
    "login",
    "dashboard",
    "panel",
    "console",
    "management",
    "sign in",
    "grafana",
    "kibana",
    "jenkins",
    "portainer",
    "traefik",
    "phpmyadmin",
    "solr",
]

SECURITY_HEADERS: dict[str, dict[str, Any]] = {
    "Strict-Transport-Security": {
        "points": 15,
        "bonus_check": lambda v: (
            5 if ("includesubdomains" in v.lower() and "preload" in v.lower()) else 0
        ),
        "solution": (
            "Set the Strict-Transport-Security header with a long max-age "
            "(at least 31536000), includeSubDomains, and preload directives."
        ),
    },
    "Content-Security-Policy": {
        "points": 15,
        "bonus_check": lambda v: (
            0 if ("unsafe-inline" in v.lower() or "unsafe-eval" in v.lower()) else 5
        ),
        "solution": (
            "Implement a Content-Security-Policy header that restricts script "
            "sources. Avoid 'unsafe-inline' and 'unsafe-eval' directives."
        ),
    },
    "X-Frame-Options": {
        "points": 10,
        "bonus_check": lambda _: 0,
        "solution": "Set X-Frame-Options to DENY or SAMEORIGIN to prevent clickjacking.",
    },
    "X-Content-Type-Options": {
        "points": 10,
        "bonus_check": lambda _: 0,
        "solution": "Set X-Content-Type-Options to 'nosniff' to prevent MIME-type sniffing.",
    },
    "Permissions-Policy": {
        "points": 10,
        "bonus_check": lambda _: 0,
        "solution": (
            "Set a Permissions-Policy header restricting access to browser features "
            "such as camera, microphone, and geolocation."
        ),
    },
    "Referrer-Policy": {
        "points": 10,
        "bonus_check": lambda _: 0,
        "solution": (
            "Set the Referrer-Policy header to 'strict-origin-when-cross-origin' "
            "or a more restrictive value."
        ),
    },
    "X-XSS-Protection": {
        "points": 5,
        "bonus_check": lambda _: 0,
        "solution": (
            "Set X-XSS-Protection to '1; mode=block'. Although deprecated in modern "
            "browsers, it provides defence-in-depth for older user agents."
        ),
    },
}

DIRECTORY_PATHS: list[str] = [
    "/images/",
    "/uploads/",
    "/assets/",
    "/static/",
    "/backup/",
    "/files/",
    "/data/",
    "/media/",
    "/docs/",
    "/documents/",
    "/downloads/",
    "/tmp/",
    "/temp/",
    "/logs/",
    "/includes/",
    "/css/",
    "/js/",
]

SENSITIVE_FILES: dict[str, dict[str, str]] = {
    "/backup.zip": {"risk": "High", "desc": "Backup archive"},
    "/backup.tar.gz": {"risk": "High", "desc": "Backup archive"},
    "/backup.sql": {"risk": "High", "desc": "Database backup"},
    "/db.sql": {"risk": "High", "desc": "Database dump"},
    "/database.sql": {"risk": "High", "desc": "Database dump"},
    "/dump.sql": {"risk": "High", "desc": "Database dump"},
    "/.env": {"risk": "High", "desc": "Environment configuration (may contain credentials)"},
    "/config.php.bak": {"risk": "High", "desc": "Backup configuration file"},
    "/web.config.bak": {"risk": "High", "desc": "Backup web server configuration"},
    "/wp-config.php.bak": {"risk": "High", "desc": "WordPress configuration backup"},
    "/.htaccess": {"risk": "Medium", "desc": "Apache configuration file"},
    "/.git/config": {"risk": "Medium", "desc": "Git repository configuration"},
    "/.git/HEAD": {"risk": "Medium", "desc": "Git repository metadata"},
    "/.svn/entries": {"risk": "Medium", "desc": "SVN repository metadata"},
    "/.svn/wc.db": {"risk": "Medium", "desc": "SVN working copy database"},
    "/robots.txt": {"risk": "Informational", "desc": "Robots exclusion file"},
    "/sitemap.xml": {"risk": "Informational", "desc": "Site map"},
}

RANSOMWARE_PORTS: dict[int, dict[str, str]] = {
    3389: {"service": "RDP", "risk": "Critical"},
    445: {"service": "SMB", "risk": "Critical"},
    5985: {"service": "WinRM HTTP", "risk": "High"},
    5986: {"service": "WinRM HTTPS", "risk": "High"},
    1433: {"service": "MSSQL", "risk": "High"},
    3306: {"service": "MySQL", "risk": "High"},
    5432: {"service": "PostgreSQL", "risk": "High"},
    27017: {"service": "MongoDB", "risk": "High"},
    6379: {"service": "Redis", "risk": "High"},
    9200: {"service": "Elasticsearch", "risk": "High"},
}


# ---------------------------------------------------------------------------
# Check 1: Exposed Admin Panels
# ---------------------------------------------------------------------------

def _has_login_form(soup: Any) -> bool:
    """Return True if the page contains a form with a password input."""
    for form in soup.find_all("form"):
        if form.find("input", attrs={"type": "password"}):
            return True
    return False


def _has_admin_keywords(text: str) -> bool:
    """Return True if the text contains admin-related keywords."""
    lower = text.lower()
    matches = sum(1 for kw in ADMIN_KEYWORDS if kw in lower)
    return matches >= 2


def _has_admin_title(soup: Any) -> bool:
    """Return True if the page title contains admin-related words."""
    title_tag = soup.find("title")
    if not title_tag:
        return False
    title = title_tag.get_text().lower()
    return any(kw in title for kw in ADMIN_TITLE_KEYWORDS)


def _is_soft_404(response_text: str, soup: Any) -> bool:
    """Heuristic check for soft 404 pages."""
    lower = response_text.lower()
    indicators = ["page not found", "404", "not found", "does not exist", "no such page"]
    title_tag = soup.find("title")
    if title_tag:
        title = title_tag.get_text().lower()
        if any(ind in title for ind in indicators):
            return True
    if lower.count("not found") >= 2:
        return True
    return False


def check_admin_panels(
    session: Any, target: str, timeout: int = 10
) -> list[dict[str, Any]]:
    """Probe for exposed admin interfaces."""
    alerts: list[dict[str, Any]] = []
    target = target.rstrip("/")

    homepage_resp, _ = fetch_page(session, target, timeout=timeout)
    homepage_length = len(homepage_resp.text) if homepage_resp else 0
    homepage_title = ""
    if homepage_resp:
        hp_soup = parse_html(homepage_resp.text)
        title_tag = hp_soup.find("title")
        if title_tag:
            homepage_title = title_tag.get_text().strip()

    for path in ADMIN_PATHS:
        url = f"{target}{path}"
        resp, err = fetch_page(session, url, timeout=timeout)
        if err or resp is None:
            continue
        if resp.status_code != 200:
            continue
        body = resp.text
        if len(body) < 500:
            continue
        if homepage_length and abs(len(body) - homepage_length) < 50:
            soup_check = parse_html(body)
            t = soup_check.find("title")
            if t and t.get_text().strip() == homepage_title:
                continue

        soup = parse_html(body)
        if _is_soft_404(body, soup):
            continue

        has_form = _has_login_form(soup)
        has_keywords = _has_admin_keywords(body)
        has_title = _has_admin_title(soup)

        if not (has_form or has_keywords or has_title):
            continue

        is_dashboard = has_keywords and not has_form
        risk = "High" if is_dashboard else "Medium"
        iface_type = "dashboard/console" if is_dashboard else "login page"

        alerts.append(make_alert(
            risk=risk,
            alert_name=f"Exposed Administrative Interface: {path}",
            url=url,
            description=(
                f"An administrative interface ({iface_type}) was detected at {path}. "
                "Exposed admin panels are a primary target for credential-stuffing "
                "and brute-force attacks used in ransomware campaigns."
            ),
            solution=(
                "Restrict access to administrative interfaces by IP allowlist, VPN, "
                "or remove them from public-facing infrastructure. Enforce "
                "multi-factor authentication on all admin endpoints."
            ),
            cweid="284",
            reference="https://cwe.mitre.org/data/definitions/284.html",
        ))

    return alerts


# ---------------------------------------------------------------------------
# Check 2: Security Headers
# ---------------------------------------------------------------------------

def check_security_headers(
    session: Any, target: str, timeout: int = 10
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Check security headers. Returns (alerts, header_details)."""
    alerts: list[dict[str, Any]] = []
    header_details: dict[str, Any] = {
        "present": {},
        "missing": [],
        "score": 0,
        "max_score": 100,
    }

    resp, err = fetch_page(session, target, timeout=timeout)
    if err or resp is None:
        header_details["error"] = err or "No response received"
        return alerts, header_details

    total_points = 0
    for header_name, config in SECURITY_HEADERS.items():
        value = resp.headers.get(header_name)
        if value:
            points = config["points"]
            bonus = config["bonus_check"](value)
            total_points += points + bonus
            header_details["present"][header_name] = {
                "value": value,
                "points": points,
                "bonus": bonus,
            }
        else:
            header_details["missing"].append(header_name)
            alerts.append(make_alert(
                risk="Low",
                alert_name=f"Missing Security Header: {header_name}",
                url=target,
                description=(
                    f"The HTTP response is missing the {header_name} header. "
                    "Missing security headers weaken the browser-side defences "
                    "available to users and increase the attack surface for "
                    "phishing and drive-by-download attacks commonly used "
                    "in ransomware delivery."
                ),
                solution=config["solution"],
                cweid="693",
                reference="https://cwe.mitre.org/data/definitions/693.html",
            ))

    header_details["score"] = min(total_points, 100)
    return alerts, header_details


# ---------------------------------------------------------------------------
# Check 3: Directory Listing
# ---------------------------------------------------------------------------

_DIR_LISTING_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"<title>\s*Index of\s", re.IGNORECASE),
    re.compile(r"<h1>\s*Index of\s", re.IGNORECASE),
    re.compile(r"Directory listing for\s", re.IGNORECASE),
    re.compile(r"\[To Parent Directory\]", re.IGNORECASE),
]


def check_directory_listing(
    session: Any, target: str, timeout: int = 10
) -> list[dict[str, Any]]:
    """Check for directory listing on common paths."""
    alerts: list[dict[str, Any]] = []
    target = target.rstrip("/")

    for path in DIRECTORY_PATHS:
        url = f"{target}{path}"
        resp, err = fetch_page(session, url, timeout=timeout)
        if err or resp is None:
            continue
        if resp.status_code != 200:
            continue
        body = resp.text
        if any(pat.search(body) for pat in _DIR_LISTING_PATTERNS):
            alerts.append(make_alert(
                risk="Low",
                alert_name=f"Directory Listing Enabled: {path}",
                url=url,
                description=(
                    f"Directory listing is enabled at {path}, exposing the contents "
                    "of the directory to anyone. Attackers use directory listings "
                    "to discover backup files, configuration files, and other "
                    "sensitive resources that facilitate ransomware attacks."
                ),
                solution=(
                    "Disable directory listing in the web server configuration. "
                    "For Apache, remove 'Options Indexes' or add 'Options -Indexes'. "
                    "For Nginx, remove 'autoindex on'."
                ),
                cweid="548",
                reference="https://cwe.mitre.org/data/definitions/548.html",
            ))

    return alerts


# ---------------------------------------------------------------------------
# Check 4: Exposed Backup / Sensitive Files
# ---------------------------------------------------------------------------

def _analyse_robots_txt(body: str, target: str) -> list[dict[str, Any]]:
    """Parse robots.txt for sensitive Disallow entries."""
    alerts: list[dict[str, Any]] = []
    sensitive_patterns = [
        "admin", "backup", "config", "database", "db", "dump",
        "secret", "private", "internal", "staging", "dev",
        "credentials", "password", "key", "token", ".env",
        "wp-admin", "cpanel", "phpmyadmin",
    ]
    for line in body.splitlines():
        line = line.strip()
        if not line.lower().startswith("disallow:"):
            continue
        path = line.split(":", 1)[1].strip()
        if not path or path == "/":
            continue
        if any(pat in path.lower() for pat in sensitive_patterns):
            alerts.append(make_alert(
                risk="Informational",
                alert_name=f"Robots.txt Discloses Sensitive Path: {path}",
                url=f"{target.rstrip('/')}/robots.txt",
                description=(
                    f"The robots.txt file discloses a potentially sensitive path: {path}. "
                    "While robots.txt is intended for search engine crawlers, attackers "
                    "routinely inspect it to discover hidden administrative or sensitive areas."
                ),
                solution=(
                    "Avoid listing sensitive paths in robots.txt. Use proper access "
                    "controls instead of relying on obscurity."
                ),
                cweid="538",
                reference="https://cwe.mitre.org/data/definitions/538.html",
            ))
    return alerts


def check_exposed_files(
    session: Any, target: str, timeout: int = 10
) -> list[dict[str, Any]]:
    """Check for exposed backup/sensitive files."""
    alerts: list[dict[str, Any]] = []
    target = target.rstrip("/")

    for path, meta in SENSITIVE_FILES.items():
        url = f"{target}{path}"
        resp, err = fetch_page(session, url, timeout=timeout)
        if err or resp is None:
            continue
        if resp.status_code != 200:
            continue

        content_type = resp.headers.get("Content-Type", "").lower()
        body = resp.text

        if path == "/robots.txt":
            if body.strip():
                alerts.extend(_analyse_robots_txt(body, target))
            continue

        if path == "/sitemap.xml":
            if "urlset" in body.lower() or "sitemapindex" in body.lower():
                alerts.append(make_alert(
                    risk="Informational",
                    alert_name="Sitemap.xml Accessible",
                    url=url,
                    description=(
                        "A sitemap.xml file is publicly accessible. While not a "
                        "vulnerability itself, it can help attackers map the "
                        "application structure."
                    ),
                    solution="Review sitemap contents for sensitive URL disclosure.",
                    cweid="538",
                ))
            continue

        if path in ("/.git/config", "/.git/HEAD"):
            if "[core]" in body or "ref:" in body:
                alerts.append(make_alert(
                    risk="Medium",
                    alert_name=f"Exposed Version Control: {path}",
                    url=url,
                    description=(
                        f"The Git repository metadata file at {path} is publicly "
                        "accessible. An attacker can reconstruct the source code "
                        "repository, potentially revealing credentials, API keys, "
                        "and application logic useful for targeted ransomware attacks."
                    ),
                    solution=(
                        "Block access to .git directories in the web server "
                        "configuration. Move version control data outside the "
                        "web root."
                    ),
                    cweid="538",
                    reference="https://cwe.mitre.org/data/definitions/538.html",
                ))
            continue

        if path in ("/.svn/entries", "/.svn/wc.db"):
            if resp.status_code == 200 and len(body) > 10:
                alerts.append(make_alert(
                    risk="Medium",
                    alert_name=f"Exposed Version Control: {path}",
                    url=url,
                    description=(
                        f"The SVN repository metadata at {path} is publicly accessible. "
                        "An attacker can use this to reconstruct source code and "
                        "discover sensitive information."
                    ),
                    solution=(
                        "Block access to .svn directories in the web server "
                        "configuration."
                    ),
                    cweid="538",
                    reference="https://cwe.mitre.org/data/definitions/538.html",
                ))
            continue

        is_binary = (
            "octet-stream" in content_type
            or "zip" in content_type
            or "gzip" in content_type
            or "sql" in content_type
            or "tar" in content_type
        )
        is_config = any(
            path.endswith(ext)
            for ext in (".env", ".bak", ".sql", ".htaccess")
        )

        if is_binary or is_config:
            if len(resp.content) > 0:
                alerts.append(make_alert(
                    risk=meta["risk"],
                    alert_name=f"Exposed Sensitive File: {path}",
                    url=url,
                    description=(
                        f"A {meta['desc']} was found at {path}. "
                        "Exposed backup and configuration files are a high-value "
                        "target for attackers seeking credentials, database dumps, "
                        "or application internals to facilitate ransomware deployment."
                    ),
                    solution=(
                        "Remove sensitive files from the web root or restrict access "
                        "via web server configuration. Implement a deployment "
                        "checklist that prevents backup files from being published."
                    ),
                    cweid="538",
                    reference="https://cwe.mitre.org/data/definitions/538.html",
                ))

    return alerts


# ---------------------------------------------------------------------------
# Check 5: Network Port Scan
# ---------------------------------------------------------------------------

def _resolve_host(target: str) -> str:
    """Extract and resolve the hostname from a target URL."""
    parsed = urlparse(target)
    hostname = parsed.hostname or parsed.path
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        if results:
            return results[0][4][0]
    except socket.gaierror:
        pass
    return hostname


def check_network_ports(
    target_host: str,
    ports: list[int] | None = None,
    timeout: int = 3,
) -> list[dict[str, Any]]:
    """TCP connect scan on ransomware-relevant ports. Stdlib socket only."""
    alerts: list[dict[str, Any]] = []
    ip_address = _resolve_host(target_host)
    scan_ports = ports if ports is not None else list(RANSOMWARE_PORTS.keys())

    for port in scan_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip_address, port))
            sock.close()
        except OSError:
            continue

        if result == 0:
            port_info = RANSOMWARE_PORTS.get(port, {"service": "Unknown", "risk": "High"})
            service = port_info["service"]
            risk = port_info["risk"]

            alerts.append(make_alert(
                risk=risk,
                alert_name=f"Exposed Service Port: {service} ({port})",
                url=f"tcp://{ip_address}:{port}",
                description=(
                    f"Port {port} ({service}) is open and reachable from the Internet. "
                    f"{service} is a service commonly exploited in ransomware campaigns "
                    "for initial access, lateral movement, or data exfiltration."
                ),
                solution=(
                    f"Restrict access to port {port} ({service}) using firewall rules. "
                    "If the service is required, place it behind a VPN or zero-trust "
                    "network access solution and enforce strong authentication."
                ),
                cweid="284",
                reference="https://cwe.mitre.org/data/definitions/284.html",
            ))

    return alerts


# ---------------------------------------------------------------------------
# Readiness Score
# ---------------------------------------------------------------------------

def compute_readiness_score(alerts: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute aggregate ransomware readiness score from alerts."""
    score = 100
    breakdown: dict[str, dict[str, Any]] = {
        "admin_panels": {"max": 20, "earned": 20, "findings": 0},
        "security_headers": {"max": 20, "earned": 20, "findings": 0},
        "directory_listings": {"max": 10, "earned": 10, "findings": 0},
        "exposed_files": {"max": 20, "earned": 20, "findings": 0},
        "network_services": {"max": 20, "earned": 20, "findings": 0},
        "strong_config": {"max": 10, "earned": 10, "findings": 0},
    }

    for alert in alerts:
        name = alert.get("alert", alert.get("name", ""))
        name_lower = name.lower()

        if "administrative interface" in name_lower:
            breakdown["admin_panels"]["findings"] += 1
            breakdown["admin_panels"]["earned"] = 0
        elif "missing security header" in name_lower:
            breakdown["security_headers"]["findings"] += 1
        elif "directory listing" in name_lower:
            breakdown["directory_listings"]["findings"] += 1
            breakdown["directory_listings"]["earned"] = 0
        elif "exposed sensitive file" in name_lower or "exposed version control" in name_lower:
            breakdown["exposed_files"]["findings"] += 1
            breakdown["exposed_files"]["earned"] = 0
        elif "exposed service port" in name_lower:
            breakdown["network_services"]["findings"] += 1
            breakdown["network_services"]["earned"] = 0
        elif "robots.txt" in name_lower or "sitemap" in name_lower:
            pass

    header_findings = breakdown["security_headers"]["findings"]
    total_headers = len(SECURITY_HEADERS)
    if header_findings > 0:
        ratio = 1.0 - (header_findings / total_headers)
        breakdown["security_headers"]["earned"] = round(20 * ratio)

    hsts_missing = any(
        "Strict-Transport-Security" in a.get("alert", a.get("name", ""))
        for a in alerts
    )
    csp_missing = any(
        "Content-Security-Policy" in a.get("alert", a.get("name", ""))
        for a in alerts
    )
    if hsts_missing or csp_missing:
        breakdown["strong_config"]["earned"] = 0

    score = sum(cat["earned"] for cat in breakdown.values())

    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 55:
        grade = "C"
    elif score >= 35:
        grade = "D"
    else:
        grade = "F"

    return {"score": score, "grade": grade, "breakdown": breakdown}


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_scan(
    target: str,
    *,
    confirm: bool = False,
    network_scan: bool = False,
    network_ports: list[int] | None = None,
    check_admin_paths: bool = True,
    timeout: int = 10,
    dry_run: bool = False,
) -> list[dict[str, Any]]:
    """Main entry point. Returns alerts in zap_scan format."""
    target = target.rstrip("/")
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    checks = []
    if check_admin_paths:
        checks.append("Exposed Admin Panels (passive)")
    checks.append("Security Headers Assessment (passive)")
    checks.append("Directory Listing Detection (passive)")
    checks.append("Exposed Backup/Sensitive Files (passive)")
    if network_scan:
        checks.append("Network Port Scan (active, requires --confirm)")

    if dry_run:
        print_dry_run(
            "ransomware_readiness",
            target,
            checks,
            network_scan=network_scan,
            confirm=confirm,
            timeout=timeout,
        )
        return []

    audit_log("RANSOMWARE_SCAN_START", target, "ransomware_readiness")
    session = get_session(timeout=timeout)
    all_alerts: list[dict[str, Any]] = []

    if check_admin_paths:
        print("  [1/5] Checking for exposed admin panels ...")
        all_alerts.extend(check_admin_panels(session, target, timeout=timeout))

    print("  [2/5] Assessing security headers ...")
    header_alerts, header_details = check_security_headers(session, target, timeout=timeout)
    all_alerts.extend(header_alerts)
    header_score = header_details.get("score", 0)
    print(f"        Security Headers Score: {header_score}/100")

    print("  [3/5] Checking for directory listings ...")
    all_alerts.extend(check_directory_listing(session, target, timeout=timeout))

    print("  [4/5] Checking for exposed backup/sensitive files ...")
    all_alerts.extend(check_exposed_files(session, target, timeout=timeout))

    if network_scan:
        if not confirm:
            print(
                "  [5/5] Network port scan SKIPPED (requires both "
                "--network-scan and --confirm)"
            )
        else:
            interactive_confirm(
                target,
                "Network Port Scan",
                "WARNING: This will perform a TCP connect scan against the target host.\n"
                "Network scanning may trigger intrusion detection systems (IDS/IPS)\n"
                "and could be logged by the target's security infrastructure.\n"
                "Only proceed if you have explicit authorisation to scan this host.",
            )
            print("  [5/5] Scanning network ports ...")
            all_alerts.extend(
                check_network_ports(target, ports=network_ports, timeout=3)
            )

    readiness = compute_readiness_score(all_alerts)
    print(
        f"\n  Ransomware Readiness Score: {readiness['score']}/100 "
        f"(Grade: {readiness['grade']})"
    )

    audit_log(
        "RANSOMWARE_SCAN_END",
        target,
        "ransomware_readiness",
        extra=(
            f"alerts={len(all_alerts)} "
            f"score={readiness['score']} "
            f"grade={readiness['grade']}"
        ),
    )

    return all_alerts


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ransomware_readiness",
        description=(
            "Assess an organisation's web-facing ransomware exposure "
            "(DORA Article 24)."
        ),
    )
    p.add_argument(
        "--target",
        required=True,
        help="Target URL, e.g. https://example.com",
    )
    p.add_argument(
        "--confirm",
        action="store_true",
        help="Authorise active checks (required for --network-scan)",
    )
    p.add_argument(
        "--network-scan",
        action="store_true",
        dest="network_scan",
        help="Enable TCP port scan for ransomware-relevant services",
    )
    p.add_argument(
        "--network-ports",
        type=lambda s: [int(p) for p in s.split(",")],
        default=None,
        dest="network_ports",
        help="Comma-separated list of ports to scan (default: built-in ransomware ports)",
    )
    p.add_argument(
        "--no-admin-check",
        action="store_true",
        dest="no_admin_check",
        help="Skip the admin panel discovery check",
    )
    p.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="HTTP request timeout in seconds (default: 10)",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        dest="dry_run",
        help="Print planned checks without executing",
    )
    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    alerts = run_scan(
        args.target,
        confirm=args.confirm,
        network_scan=args.network_scan,
        network_ports=args.network_ports,
        check_admin_paths=not args.no_admin_check,
        timeout=args.timeout,
        dry_run=args.dry_run,
    )

    if not args.dry_run:
        print(f"\n  Total findings: {len(alerts)}")
        severity_counts: dict[str, int] = {}
        for a in alerts:
            sev = a.get("risk", "Informational")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        for sev in ("Critical", "High", "Medium", "Low", "Informational"):
            count = severity_counts.get(sev, 0)
            if count:
                print(f"    {sev}: {count}")


if __name__ == "__main__":
    main()
