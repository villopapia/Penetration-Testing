# DORA Article 24 Penetration Testing Toolkit

## Project overview

Automated vulnerability assessment toolkit for CySEC ICT regulatory assessments under DORA Article 24. Combines OWASP ZAP scanning with custom Python security modules to produce structured compliance reports.

## Entry points

Two supported coverage modes:

**Full-coverage path (ZAP available):**
- `assess.py` — Full assessment: ZAP scan + custom modules, single DORA report. **Primary entry point.** Passes `scan_type="full"` to the report pipeline.
- `zap_scan.py` — ZAP-only scan with report generation.
- `combined_report.py` — Merges ZAP JSON + manual findings YAML into one report.

**Standalone no-ZAP path (officially supported reduced-scope mode):**
- `run_modules.py` — Custom Python modules only. No ZAP daemon, no `ZAP_API_KEY`, and `zaproxy`/`zapv2` need not be installed (`zapv2` is only imported inside ZAP-specific functions in `zap_scan.py`, never at import time, so `run_modules.py` can import the report pipeline without it). Passes `scan_type="modules"`.
- `gui_app.py` — Tkinter GUI wrapper around `run_modules.py`'s module scan, for running without a terminal. Replaces the CLI's `input()`-based active-test confirmation with a dialog box (see `App._gui_confirm` / `_patch_confirm_prompts`). Package it into a standalone Windows exe with `build_exe.py` (PyInstaller, `--onefile --windowed`) for handing to users with no Python/pip/terminal access. That build intentionally excludes `playwright`/`weasyprint` (native binaries, not worth bundling) and IPython's transitive stack (dragged in only by a dead code path in `python-dotenv`, ~40MB of dead weight).

### No-ZAP mode: what it does and does NOT cover

The no-ZAP path runs only the named custom module checks (auth, supply-chain, TLS, API discovery, admin-panel/security-header, prompt-injection, authenticated crawl). It does **NOT** perform OWASP ZAP's active vulnerability/injection scan — no generalized XSS, SQL injection, command injection, or path-traversal testing, and no spider-driven active scan. Use `assess.py` (with ZAP running) for full coverage.

When `scan_type == "modules"`, the report is honestly re-labeled so a reader cannot mistake "ZAP was not run" for "ZAP ran and found nothing":
- Detection helper: `_is_modules_only(scan_type)` in `zap_scan.py`.
- Executive Summary: methodology reads "custom security modules only — OWASP ZAP active scan NOT performed", plus a prominent reduced-scope banner.
- Scope & Methodology (Section 5): Tools Used states ZAP was not used; Test Types Performed lists the actual modules run (via `_MODULE_DISPLAY_NAMES` + the `modules_run` list threaded through `_report_md`/`_report_html`/`_report_json` → `_build_report_sections`); Test Types Not Performed explicitly calls out the missing active/injection scan and which modules weren't selected.
- DORA Alignment (Section 6): adds a scope-limitation note that the mapping reflects only the named checks, not a full active vulnerability assessment.
- JSON report: `summary.zap_performed=false`, `summary.modules_run`, and `summary.coverage_note`.

## Configuration

All defaults live in `.env` (loaded via python-dotenv):
- `ZAP_API_KEY`, `ENTITY_NAME`, `ENTITY_LEI`, `ASSESSOR_NAME`, `REPORT_FORMAT`, `CUSTOM_MODULES`
- `REPORT_FORMAT` accepts `md`, `html`, `json`, or `pdf` (pdf requires `weasyprint`, renders via HTML first).
- Minimal command: `python assess.py --target https://example.com`

## Custom modules (in `modules/`)

| Module file | CLI name | Active? | What it tests |
|---|---|---|---|
| `auth_test.py` | `auth` | Yes | Login discovery, cleartext, CSRF, default creds |
| `supply_chain.py` | `supply-chain` | No | JS library CVEs, SRI, manifests |
| `prompt_injection.py` | `prompt-injection` | Yes | LLM/chatbot detection, prompt injection |
| `ransomware_readiness.py` | `ransomware` | No* | Admin panels, security headers, directory listing |
| `authenticated_scan.py` | `authenticated-scan` | Yes | Auth crawl, broken access control, IDOR |
| `tls_check.py` | `tls` | No | Certs, protocol versions, ciphers, HSTS |
| `api_discovery.py` | `api-discovery` | No | OpenAPI/Swagger, JS endpoints, GraphQL |

*ransomware port scan requires `--network-scan`

Active modules require `--confirm` (or `--modules-confirm` in assess.py).

## Shared code (`modules/common.py`)

- `make_alert()` — All findings must use this. Returns dict with: riskcode, risk, alert, name, url, description, solution, cweid, wascid, reference, evidence.
- `load_lines()` — Load wordlist files (strips comments/blanks).
- `extract_script_sources()` — Extract `<script src>` and `<link href>` from HTML.
- `get_session()`, `fetch_page()`, `parse_html()`, `resolve_url()`, `is_same_origin()` — HTTP/HTML helpers.
- `audit_log()` — Structured audit logging.

## Report pipeline (`zap_scan.py`)

1. Raw alerts collected from ZAP and/or custom modules
2. `_parse_alerts()` — normalises raw alerts
3. `_prepare_findings()` — deduplicates by alert name, merges manual findings
4. `_build_report_sections()` — assembles 7 sections
5. Output via `_report_md()`, `_report_html()`, or `_report_json()`

Seven report sections: Executive Summary, Risk Methodology, Technical Findings, Recommendations, Scope & Methodology, DORA Alignment (conditional), Disclaimer.

DORA mapping uses `_DORA_KEYWORD_MAP` to categorise findings into ICT risk articles.

## Ground rules

- All alerts via `make_alert()` — never raw dicts.
- Active tests (sending payloads, login attempts, IDOR probes) gated behind `confirm=False` check.
- Passive checks (TLS, headers, discovery) don't need `--confirm`.
- New parameters must have safe defaults for backward compatibility.
- No external dependencies beyond `requirements.txt` for core modules (stdlib ssl/socket for TLS).

## Testing

```bash
pip install -r requirements-dev.txt
pytest tests/ -v
```

- Tests use `FakeSession`/`FakeResponse` from `tests/conftest.py` — no real network I/O.
- `conftest.py` also provides `FakeCookieJar`, `SAMPLE_LOGIN_HTML`, `SAMPLE_LOGIN_HTML_ROTATED_CSRF`.
- Monkeypatch `time.sleep` in tests that hit IDOR probes or CSRF checks.

## Wordlists (`wordlists/`)

- `default_credentials.txt` — Common username:password pairs (`auth_test.py`)
- `login_paths.txt` — Candidate login page paths for discovery (`auth_test.py`)
- `api_spec_paths.txt` — OpenAPI/Swagger spec paths (`api_discovery.py`)
- `graphql_paths.txt` — GraphQL endpoint paths (`api_discovery.py`)

Note: admin panel paths (`ransomware_readiness.py`) are hardcoded in `ADMIN_PATHS`, not a wordlist file.
