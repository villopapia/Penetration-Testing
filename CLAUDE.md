# DORA Article 24 Penetration Testing Toolkit

## Project overview

Automated vulnerability assessment toolkit for CySEC ICT regulatory assessments under DORA Article 24. Combines OWASP ZAP scanning with custom Python security modules to produce structured compliance reports.

## Entry points

- `assess.py` — Full assessment: ZAP scan + custom modules, single DORA report. **Primary entry point.**
- `run_modules.py` — Custom Python modules only (no ZAP needed).
- `zap_scan.py` — ZAP-only scan with report generation.
- `combined_report.py` — Merges ZAP JSON + manual findings YAML into one report.

## Configuration

All defaults live in `.env` (loaded via python-dotenv):
- `ZAP_API_KEY`, `ENTITY_NAME`, `ENTITY_LEI`, `ASSESSOR_NAME`, `REPORT_FORMAT`, `CUSTOM_MODULES`
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

- `default_credentials.txt` — Common username:password pairs
- `admin_paths.txt` — Admin panel URL paths
- `api_spec_paths.txt` — OpenAPI/Swagger spec paths
- `graphql_paths.txt` — GraphQL endpoint paths
