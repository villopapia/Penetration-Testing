"""TLS/SSL certificate and protocol testing module.

Uses only stdlib ssl/socket — no new dependencies. Every check is passive
(read-only), so no --confirm is required.
"""

from __future__ import annotations

import argparse
import datetime as dt
import socket
import ssl
from typing import Any
from urllib.parse import urlparse

from modules.common import make_alert, get_session, audit_log, print_dry_run, fetch_page

_WEAK_TLS_VERSIONS = ("TLSv1", "TLSv1.1")
_WEAK_CIPHER_STRINGS = ("RC4", "DES-CBC3-SHA", "NULL", "EXPORT", "MD5", "aNULL", "eNULL")
_CERT_EXPIRY_WARN_DAYS = 30


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_host_port(target: str) -> tuple[str, int, bool]:
    parsed = urlparse(target)
    host = parsed.hostname or parsed.path.split("/")[0]
    is_https = parsed.scheme == "https"
    default_port = 443 if is_https else 80
    port = parsed.port or default_port
    return host, port, is_https


# ---------------------------------------------------------------------------
# Certificate checks
# ---------------------------------------------------------------------------

def check_certificate(host: str, port: int, timeout: int = 10) -> dict[str, Any]:
    result: dict[str, Any] = {
        "host": host,
        "port": port,
        "trusted": False,
        "trust_error": "",
        "cert": None,
        "cipher": None,
        "protocol": None,
        "expired": False,
        "not_yet_valid": False,
        "hostname_mismatch": False,
        "self_signed": False,
        "days_until_expiry": None,
        "issuer": "",
        "subject": "",
        "not_before": None,
        "not_after": None,
    }

    # Verified connection (checks trust chain + hostname)
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                result["trusted"] = True
                result["cert"] = cert
                result["cipher"] = ssock.cipher()
                result["protocol"] = ssock.version()
                _populate_cert_dates(result, cert)
                _populate_cert_names(result, cert)
    except ssl.SSLCertVerificationError as exc:
        result["trust_error"] = str(exc)
        if "self-signed" in str(exc).lower() or "self signed" in str(exc).lower():
            result["self_signed"] = True
        if "hostname mismatch" in str(exc).lower():
            result["hostname_mismatch"] = True
    except (socket.timeout, socket.gaierror, OSError) as exc:
        result["trust_error"] = f"Connection failed: {exc}"
        return result

    # Unverified connection to get cert details even if untrusted
    if not result["trusted"]:
        try:
            ctx_noverify = ssl.create_default_context()
            ctx_noverify.check_hostname = False
            ctx_noverify.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx_noverify.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    if not cert:
                        der = ssock.getpeercert(binary_form=True)
                        if der:
                            result["cert"] = {"raw_der": True}
                    else:
                        result["cert"] = cert
                        _populate_cert_dates(result, cert)
                        _populate_cert_names(result, cert)
                    result["cipher"] = ssock.cipher()
                    result["protocol"] = ssock.version()
        except Exception:
            pass

    return result


def _populate_cert_dates(result: dict[str, Any], cert: dict) -> None:
    not_before_str = cert.get("notBefore", "")
    not_after_str = cert.get("notAfter", "")
    now = dt.datetime.now(dt.timezone.utc)

    if not_after_str:
        try:
            not_after = dt.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
            not_after = not_after.replace(tzinfo=dt.timezone.utc)
            result["not_after"] = not_after
            delta = not_after - now
            result["days_until_expiry"] = delta.days
            if delta.total_seconds() < 0:
                result["expired"] = True
        except ValueError:
            pass

    if not_before_str:
        try:
            not_before = dt.datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z")
            not_before = not_before.replace(tzinfo=dt.timezone.utc)
            result["not_before"] = not_before
            if now < not_before:
                result["not_yet_valid"] = True
        except ValueError:
            pass


def _populate_cert_names(result: dict[str, Any], cert: dict) -> None:
    subject = cert.get("subject", ())
    issuer = cert.get("issuer", ())
    result["subject"] = _dn_to_str(subject)
    result["issuer"] = _dn_to_str(issuer)


def _dn_to_str(dn_tuple: tuple) -> str:
    parts = []
    for rdn in dn_tuple:
        for attr_type, attr_value in rdn:
            parts.append(f"{attr_type}={attr_value}")
    return ", ".join(parts)


def build_cert_alerts(
    host: str, port: int, target_url: str, cert_result: dict[str, Any],
) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []

    if not cert_result.get("cert"):
        if cert_result.get("trust_error"):
            alerts.append(make_alert(
                risk="High",
                alert_name="TLS Connection Failed",
                url=target_url,
                description=f"Could not establish TLS connection to {host}:{port}: {cert_result['trust_error']}",
                solution="Verify the server's TLS configuration and certificate.",
                cweid="295",
            ))
        return alerts

    # Untrusted / self-signed
    if not cert_result["trusted"]:
        risk = "High"
        name = "Self-Signed Certificate" if cert_result["self_signed"] else "Untrusted TLS Certificate"
        alerts.append(make_alert(
            risk=risk,
            alert_name=name,
            url=target_url,
            description=(
                f"The TLS certificate for {host}:{port} is not trusted: "
                f"{cert_result['trust_error']}"
            ),
            solution="Use a certificate signed by a trusted Certificate Authority.",
            cweid="295",
            evidence=cert_result.get("issuer", ""),
        ))

    # Expired
    if cert_result["expired"]:
        alerts.append(make_alert(
            risk="Critical",
            alert_name="Expired TLS Certificate",
            url=target_url,
            description=(
                f"The TLS certificate for {host}:{port} expired on "
                f"{cert_result['not_after']}."
            ),
            solution="Renew the TLS certificate immediately.",
            cweid="298",
        ))

    # Nearing expiry
    elif cert_result["days_until_expiry"] is not None and cert_result["days_until_expiry"] <= _CERT_EXPIRY_WARN_DAYS:
        alerts.append(make_alert(
            risk="Medium",
            alert_name="TLS Certificate Nearing Expiry",
            url=target_url,
            description=(
                f"The TLS certificate for {host}:{port} expires in "
                f"{cert_result['days_until_expiry']} days (on {cert_result['not_after']})."
            ),
            solution=(
                f"Renew the certificate before it expires. "
                f"Current expiry: {cert_result['not_after']}."
            ),
        ))

    # Not yet valid
    if cert_result["not_yet_valid"]:
        alerts.append(make_alert(
            risk="High",
            alert_name="TLS Certificate Not Yet Valid",
            url=target_url,
            description=(
                f"The TLS certificate for {host}:{port} is not valid until "
                f"{cert_result['not_before']}."
            ),
            solution="Check the server clock and certificate validity dates.",
        ))

    # Hostname mismatch
    if cert_result["hostname_mismatch"]:
        alerts.append(make_alert(
            risk="High",
            alert_name="TLS Certificate Hostname Mismatch",
            url=target_url,
            description=(
                f"The TLS certificate for {host}:{port} does not match the "
                f"requested hostname. Subject: {cert_result.get('subject', 'unknown')}."
            ),
            solution="Use a certificate that matches the server hostname.",
            cweid="297",
        ))

    return alerts


# ---------------------------------------------------------------------------
# Protocol version checks
# ---------------------------------------------------------------------------

_TLS_VERSION_MAP: dict[str, int] = {}

# Build version map dynamically since not all Python builds have all versions
for _name, _attr in [
    ("TLSv1", "TLSv1"),
    ("TLSv1.1", "TLSv1_1"),
    ("TLSv1.2", "TLSv1_2"),
    ("TLSv1.3", "TLSv1_3"),
]:
    _val = getattr(ssl.TLSVersion, _attr, None)
    if _val is not None:
        _TLS_VERSION_MAP[_name] = _val


def check_protocol_versions(
    host: str, port: int, timeout: int = 10,
) -> dict[str, str]:
    """Test each TLS version independently. Returns {version: "supported"|"unsupported"|error}."""
    results: dict[str, str] = {}

    for ver_name, ver_const in _TLS_VERSION_MAP.items():
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ver_const
            ctx.maximum_version = ver_const

            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    actual = ssock.version()
                    results[ver_name] = "supported"
        except ssl.SSLError:
            results[ver_name] = "unsupported"
        except (socket.timeout, socket.gaierror, OSError) as exc:
            results[ver_name] = f"error: {exc}"

    return results


def build_protocol_alerts(
    target_url: str, version_status: dict[str, str],
) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []

    for ver in _WEAK_TLS_VERSIONS:
        status = version_status.get(ver, "unknown")
        if status == "supported":
            alerts.append(make_alert(
                risk="High",
                alert_name=f"Deprecated TLS Version Supported: {ver}",
                url=target_url,
                description=(
                    f"The server supports {ver}, which is deprecated and known "
                    f"to have security vulnerabilities. All modern browsers have "
                    f"disabled {ver} support."
                ),
                solution=f"Disable {ver} support. Only allow TLS 1.2 and TLS 1.3.",
                cweid="326",
                evidence=f"{ver}: supported",
            ))

    # Informational: report supported versions
    supported = [v for v, s in version_status.items() if s == "supported"]
    if supported:
        alerts.append(make_alert(
            risk="Informational",
            alert_name="TLS Protocol Versions Supported",
            url=target_url,
            description=f"Supported TLS versions: {', '.join(supported)}.",
            solution="Ensure only TLS 1.2 and TLS 1.3 are enabled.",
            evidence="; ".join(f"{v}: {s}" for v, s in version_status.items()),
        ))

    return alerts


# ---------------------------------------------------------------------------
# Weak cipher checks
# ---------------------------------------------------------------------------

def check_weak_ciphers(
    host: str, port: int, timeout: int = 10,
) -> list[str]:
    """Return list of weak cipher names the server accepts."""
    weak_found: list[str] = []

    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cipher_info = ssock.cipher()
                if cipher_info:
                    cipher_name = cipher_info[0]
                    for weak in _WEAK_CIPHER_STRINGS:
                        if weak.upper() in cipher_name.upper():
                            weak_found.append(cipher_name)
                            break
    except (ssl.SSLError, socket.timeout, socket.gaierror, OSError):
        pass

    return weak_found


def build_cipher_alerts(
    target_url: str, weak_ciphers: list[str],
) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []

    if weak_ciphers:
        alerts.append(make_alert(
            risk="High",
            alert_name="Weak TLS Cipher Suite Accepted",
            url=target_url,
            description=(
                f"The server accepts weak cipher suite(s): {', '.join(weak_ciphers)}. "
                f"These ciphers are vulnerable to known attacks."
            ),
            solution=(
                "Configure the server to only accept strong cipher suites. "
                "Disable RC4, DES, NULL, EXPORT, and MD5-based ciphers."
            ),
            cweid="327",
            evidence=", ".join(weak_ciphers),
        ))

    return alerts


# ---------------------------------------------------------------------------
# HSTS check
# ---------------------------------------------------------------------------

def check_hsts(
    target_url: str, headers: dict[str, str],
) -> list[dict[str, Any]]:
    """Check for HTTP Strict Transport Security header."""
    alerts: list[dict[str, Any]] = []
    hsts = headers.get("Strict-Transport-Security", headers.get("strict-transport-security", ""))

    if not hsts:
        alerts.append(make_alert(
            risk="Medium",
            alert_name="TLS: Missing HTTP Strict Transport Security (HSTS)",
            url=target_url,
            description=(
                "The server does not send the Strict-Transport-Security header. "
                "Without HSTS, users may be vulnerable to SSL stripping attacks."
            ),
            solution="Add the Strict-Transport-Security header with a max-age of at least 31536000.",
            cweid="319",
        ))
    else:
        if "includeSubDomains" not in hsts:
            alerts.append(make_alert(
                risk="Low",
                alert_name="TLS: HSTS Missing includeSubDomains Directive",
                url=target_url,
                description=(
                    f"The HSTS header is present but does not include the "
                    f"includeSubDomains directive. Value: {hsts}"
                ),
                solution="Add includeSubDomains to the Strict-Transport-Security header.",
                evidence=hsts,
            ))

        try:
            max_age_str = hsts.split("max-age=")[1].split(";")[0].strip()
            max_age = int(max_age_str)
            if max_age < 31536000:
                alerts.append(make_alert(
                    risk="Low",
                    alert_name="TLS: HSTS max-age Too Short",
                    url=target_url,
                    description=(
                        f"The HSTS max-age is {max_age} seconds "
                        f"({max_age // 86400} days), which is less than the "
                        f"recommended minimum of 31536000 seconds (1 year)."
                    ),
                    solution="Set HSTS max-age to at least 31536000 (1 year).",
                    evidence=hsts,
                ))
        except (IndexError, ValueError):
            pass

    return alerts


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_scan(
    target: str,
    *,
    timeout: int = 10,
    dry_run: bool = False,
    session_override: Any | None = None,
) -> list[dict[str, Any]]:
    """Orchestrate all TLS/SSL checks. Fully passive — no --confirm needed."""
    target = target.rstrip("/")
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    host, port, is_https = _get_host_port(target)

    checks = [
        "TLS Certificate Validation",
        "TLS Protocol Version Testing",
        "Weak Cipher Suite Detection",
        "HSTS Header Assessment",
    ]

    if dry_run:
        print_dry_run("tls_check", target, checks, host=host, port=port)
        return []

    audit_log("TLS_SCAN_START", target, "tls_check")
    alerts: list[dict[str, Any]] = []

    # Certificate
    print(f"  [1/4] Checking TLS certificate for {host}:{port} ...")
    if is_https:
        cert_result = check_certificate(host, port, timeout=timeout)
        alerts.extend(build_cert_alerts(host, port, target, cert_result))
        print(f"        Trusted: {cert_result['trusted']}, "
              f"Protocol: {cert_result.get('protocol', 'unknown')}")
    else:
        alerts.append(make_alert(
            risk="High",
            alert_name="No TLS: Site Served Over HTTP",
            url=target,
            description="The target is served over plain HTTP without TLS encryption.",
            solution="Enable HTTPS with a valid TLS certificate.",
            cweid="319",
        ))

    # Protocol versions
    if is_https:
        print(f"  [2/4] Testing TLS protocol versions ...")
        version_status = check_protocol_versions(host, port, timeout=timeout)
        alerts.extend(build_protocol_alerts(target, version_status))
        supported = [v for v, s in version_status.items() if s == "supported"]
        print(f"        Supported: {', '.join(supported) if supported else 'none detected'}")

    # Weak ciphers
    if is_https:
        print(f"  [3/4] Checking for weak cipher suites ...")
        weak = check_weak_ciphers(host, port, timeout=timeout)
        alerts.extend(build_cipher_alerts(target, weak))
        print(f"        Weak ciphers: {', '.join(weak) if weak else 'none detected'}")

    # HSTS
    print(f"  [4/4] Checking HSTS header ...")
    session = session_override or get_session(timeout=timeout)
    resp, err = fetch_page(session, target, timeout=timeout)
    if resp is not None:
        alerts.extend(check_hsts(target, dict(resp.headers)))
    else:
        print(f"        Could not fetch {target}: {err}")

    audit_log(
        "TLS_SCAN_COMPLETE", target, "tls_check",
        extra=f"alerts={len(alerts)}",
    )
    return alerts


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="tls_check",
        description="TLS/SSL certificate, protocol, and cipher assessment.",
    )
    p.add_argument("--target", required=True, help="Target URL")
    p.add_argument("--timeout", type=int, default=10, help="Socket timeout (default: 10)")
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
        print("\n[tls_check] No alerts generated.")


if __name__ == "__main__":
    main()
