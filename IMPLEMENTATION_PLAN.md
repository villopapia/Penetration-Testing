# DORA Article 24 Toolkit — Implementation Plan

Target repo: C:\Users\User\Desktop\pen\
Author: planning pass, 2026-07-17. Implementer: Opus 4.8, single session, sequential tasks.

## Ground rules for the implementer

1. Every module's `run_scan()` keeps its existing keyword-only parameters and
   return type (`list[dict]` of `make_alert()`-shaped dicts). New capabilities
   are ADDED as new keyword-only parameters with safe defaults that preserve
   current behavior when omitted.
2. Every new alert MUST be built via `modules.common.make_alert()`.
3. Every new active (state-changing / intrusive) capability MUST be gated
   behind `confirm: bool = False` and MUST call `interactive_confirm()` from
   `modules/common.py` before executing, mirroring the existing pattern in
   `auth_test.py` / `ransomware_readiness.py`.
4. Passive/read-only checks (header inspection, spec fetching, cert
   inspection, GraphQL introspection query, JS static analysis) do NOT
   require `--confirm`, consistent with `supply_chain.py` today.
5. After every task, run `python -m py_compile` on touched files and (once
   Task 1 lands) `pytest -q` before moving to the next task. Do not proceed
   to a dependent task if the previous one leaves the test suite red.
6. New third-party dependencies: only `playwright` (runtime, optional/lazy)
   and `pytest` (dev-only, new `requirements-dev.txt`). Everything else
   (TLS/cert testing, API/JS parsing, GraphQL introspection) uses stdlib
   (`ssl`, `socket`, `re`, `json`) + the existing `requests`/`bs4`.

---

## Phase 0 — Safety net (Gap 6, part 1)

### Task 1: pytest harness + baseline regression tests
**Files to create:**
- `C:\Users\User\Desktop\pen\requirements-dev.txt`
- `C:\Users\User\Desktop\pen\pytest.ini`
- `C:\Users\User\Desktop\pen\conftest.py` (repo root)
- `C:\Users\User\Desktop\pen\tests\__init__.py`
- `C:\Users\User\Desktop\pen\tests\conftest.py`
- `C:\Users\User\Desktop\pen\tests\test_zap_scan_report.py`
- `C:\Users\User\Desktop\pen\tests\test_common.py`
- `C:\Users\User\Desktop\pen\tests\test_auth_test.py`
- `C:\Users\User\Desktop\pen\tests\test_supply_chain.py`
- `C:\Users\User\Desktop\pen\tests\test_prompt_injection.py`
- `C:\Users\User\Desktop\pen\tests\test_ransomware_readiness.py`

**What to implement:**
- `requirements-dev.txt`: `pytest>=7.4.0,<9`
- `pytest.ini`:
  ```ini
  [pytest]
  testpaths = tests
  python_files = test_*.py
  ```
- Root `conftest.py`: inserts the repo root onto `sys.path` (mirrors the
  `sys.path.insert` trick already used at the top of `modules/supply_chain.py`)
  so `import zap_scan`, `from modules import ...` resolve when pytest is
  invoked from any cwd.
- `tests/conftest.py`: a `FakeSession` class implementing `.get()`, `.post()`,
  `.request()` methods (no real network I/O) returning objects that duck-type
  `requests.Response` (`.status_code`, `.text`, `.content`, `.headers` dict,
  `.cookies`, `.history`, `.url`). Provide fixtures:
  - `fake_session_factory(responses: dict[str, FakeResponse])` — routes by
    URL substring match.
  - `sample_login_html` — a fixture string containing a `<form>` with a
    password field and a hidden CSRF field (`<input type="hidden"
    name="csrf_token" value="abc123">`), used by both existing and Phase 2
    tests.
  - `tmp_audit_log(monkeypatch)` — redirects `zap_scan.AUDIT_LOG` /
    `_audit_logger` file handler to a `tmp_path` file so tests never write
    into the real `scan_audit.log`. **Edge case**: `_audit_handler` is bound
    at import time in `zap_scan.py` to `pathlib.Path("scan_audit.log")` in the
    cwd; monkeypatch `zap_scan._audit` directly (a no-op or list-appending
    stub) rather than trying to re-point the logging handler.
- `tests/test_zap_scan_report.py`: pure-function tests (no network) for
  `_parse_alerts`, `_dedupe_findings`, `_map_dora_article`,
  `_is_third_party_finding`, `_severity_counts`, `_compliance_verdict`,
  `_merge_findings`, `_report_md` (assert output file contains section
  headers `## 1. Executive Summary` ... `## 7. Disclaimer`), and
  `_map_finding_to_dora_category`. This locks in current DORA-mapping
  behavior so later tasks that add keywords can be checked for regressions.
- `tests/test_common.py`: tests for `make_alert()` (asserts all 11 keys
  present, `riskcode` mapping correct for each risk level), `is_same_origin`,
  `resolve_url`, `fetch_page` (with `FakeSession`, both success and
  `requests.RequestException` paths).
- `tests/test_auth_test.py`: tests for `discover_login_endpoints` (using
  `sample_login_html` via `FakeSession`), `check_cleartext_login`,
  `_identify_field`, `_build_form_data`. Also a test that `run_scan(...,
  confirm=False)` returns only passive alerts and never calls
  `session.post`.
- `tests/test_supply_chain.py`: `_extract_script_sources`,
  `_identify_from_url` against the real `data/js_library_signatures.json`,
  `check_sri`. Mock `lookup_cves` (monkeypatch `requests.Session.post`) to
  avoid hitting the real OSV.dev API.
- `tests/test_prompt_injection.py`: `detect_llm_features` against the real
  `data/llm_ui_signatures.json` with a `FakeSession`, `_selector_to_regex`,
  `_looks_like_system_prompt`.
- `tests/test_ransomware_readiness.py`: `check_security_headers` scoring
  math, `compute_readiness_score` breakdown, `_is_soft_404`.

**Dependencies:** none (first task).
**Complexity:** M
**New deps:** `pytest` (dev only, in `requirements-dev.txt`, NOT
`requirements.txt`).

---

## Phase 1 — Headless browser rendering (Gap 1)

### Task 2: Shared Playwright rendering helper
**Files to create:**
- `C:\Users\User\Desktop\pen\modules\browser_render.py`

**Files to modify:**
- `C:\Users\User\Desktop\pen\requirements.txt` — append
  `playwright>=1.40.0,<2` on its own line with a comment
  `# optional: headless browser rendering for JS-heavy targets (auth_test, supply_chain, prompt_injection). Run 'playwright install chromium' after pip install.`

**What to implement in `modules/browser_render.py`:**
```python
from __future__ import annotations
import dataclasses
from typing import Any

@dataclasses.dataclass
class RenderedPage:
    html: str
    final_url: str
    status: int | None
    requests: list[str]          # every resource URL the page issued (for supply_chain)
    console_errors: list[str]

def is_playwright_available() -> bool: ...
    # try: import playwright.sync_api  except ImportError: return False

class BrowserUnavailableError(RuntimeError): ...

class BrowserSession:
    """Reusable headless Chromium session. One instance per run_scan() call."""
    def __init__(self, *, headless: bool = True, nav_timeout_ms: int = 30000,
                 user_agent: str = "DORA-Art24-SecurityAssessment/1.0 "
                                    "(Authorised Regulatory Assessment Tool)"): ...
    def __enter__(self) -> "BrowserSession": ...
        # imports playwright.sync_api.sync_playwright lazily inside __enter__;
        # raises BrowserUnavailableError with a clear pip/install-chromium
        # message if import fails OR if browser launch fails (e.g. binaries
        # not installed -- playwright raises its own Error subclass; catch
        # broad Exception and re-raise as BrowserUnavailableError so callers
        # only need to catch one type).
    def __exit__(self, exc_type, exc, tb) -> None: ...
        # MUST close page/context/browser/playwright even if render() raised.
    def render(self, url: str, *, wait_for_selector: str | None = None,
               wait_until: str = "networkidle", extra_wait_ms: int = 1500,
               cookies: list[dict] | None = None,
               extra_headers: dict[str, str] | None = None) -> RenderedPage: ...
        # opens a new page in the shared context, optionally injects cookies
        # (for authenticated rendering in Phase 3), navigates, waits for
        # wait_until then, if wait_for_selector given, page.wait_for_selector
        # with a short timeout (swallow TimeoutError -- selector not
        # appearing is a valid negative result, not a crash), sleeps
        # extra_wait_ms for slow XHR-driven UI, captures page.content(),
        # page.url, response.status, collects request URLs via
        # page.on("request", ...) registered before navigation, and
        # page.on("console", ...) filtered to type=="error". Closes the page
        # (not the context) before returning so the context/cookies persist
        # for subsequent render() calls in the same BrowserSession.
```
**Edge cases the implementer must handle explicitly:**
- Playwright not installed -> every module using this helper must fall back
  to the existing `requests`-based path and print exactly one warning line,
  not fail the whole `run_scan()`.
- Playwright installed but `playwright install chromium` never run -> browser
  launch throws; treat identically to "not installed" (fallback + warning),
  not a hard error.
- Target blocks headless browsers (bot detection) -> `render()` may return a
  challenge page; this is a known limitation, not something to solve here --
  do not attempt UA spoofing beyond the existing descriptive UA string used
  by `get_session()` (keep it consistent/transparent per the tool's
  "Authorised Regulatory Assessment Tool" identification convention).

**Dependencies:** Task 1 (tests exist to pin behavior; add
`tests/test_browser_render.py` using `pytest.importorskip("playwright")` so
CI/dev machines without the browser installed don't fail the suite).
**Complexity:** M
**New deps:** `playwright` (runtime, optional).

### Task 3: `auth_test.py` — SPA-aware login discovery
**Files to modify:** `C:\Users\User\Desktop\pen\modules\auth_test.py`

**What to implement:**
- Add module-level constant:
  ```python
  _SPA_SHELL_MARKERS = (
      'id="root"', 'id="app"', 'ng-version', 'data-reactroot',
      '__next', 'data-server-rendered', 'ng-app',
  )
  def _looks_like_spa_shell(html: str) -> bool:
      lower = html.lower()
      return '<form' not in lower and any(m.lower() in lower for m in _SPA_SHELL_MARKERS)
  ```
- Modify `discover_login_endpoints()` signature to add
  `use_browser: bool = False` (keyword-only, default False = fully backward
  compatible). Logic change inside `_process_page`/the candidate-path loop:
  after the existing static fetch+parse for a URL, if `use_browser` is True
  AND `is_playwright_available()` AND (`_looks_like_spa_shell(resp.text)` OR
  zero forms found across ALL candidate paths after the static pass), render
  that specific URL with a shared `BrowserSession` (opened once, reused for
  all such URLs, closed at the end via `with`) using
  `wait_for_selector="input[type=password]"` and feed the resulting
  `RenderedPage.html` back through the SAME `_process_page` parsing you
  already have (no duplicate form-parsing logic).
- **Cost control (explicit design decision):** do NOT render all 51
  candidate paths with a browser. Only render (a) the target root always
  when `use_browser=True`, and (b) any candidate path whose static HTML
  matched `_looks_like_spa_shell`. This bounds browser page loads to a
  handful per scan instead of 51+.
- Add `use_browser: bool = False` to `run_scan()` and thread it through to
  `discover_login_endpoints`. Add it to the dry-run `checks` list
  (`"JS-rendered login discovery (Playwright)"` when `use_browser=True`).
  Add `--use-browser` flag to `_build_cli_parser()`.
- If `use_browser=True` but `is_playwright_available()` is False, print:
  `"[auth_test] --use-browser requested but Playwright is not installed/configured; falling back to static HTML discovery. Run: pip install playwright && playwright install chromium"`
  and continue with `use_browser` effectively disabled -- do not exit/crash.

**Dependencies:** Task 2.
**Complexity:** M
**New deps:** none (uses Task 2's helper).

### Task 4: `supply_chain.py` — dynamically-loaded script discovery
**Files to modify:** `C:\Users\User\Desktop\pen\modules\supply_chain.py`

**What to implement:**
- Add `use_browser: bool = False` and `session_override: requests.Session | None = None`
  to `run_scan()` (the `session_override` param is needed later by Task 10
  too -- add both now to avoid touching this function signature twice).
  Change the session line:
  `session = session_override or get_session(timeout=timeout, verify_tls=verify_tls)`.
- New function:
  ```python
  def discover_libraries_via_browser(
      base_url: str, signatures: dict[str, Any], *, timeout_ms: int = 30000,
  ) -> list[dict[str, Any]]:
      """Render base_url with BrowserSession, collect RenderedPage.requests
      (every network request the page fired, including JS-injected <script>
      tags added after load, dynamic import(), fetch()-loaded bundles), run
      each request URL through the EXISTING _identify_from_url(...) matcher.
      Returns the same shape as discover_libraries()'s return value so
      run_scan can simply concatenate both lists and de-dupe on
      f"{name}@{version}" (reuse the existing `seen` set pattern)."""
  ```
- In `run_scan`, after the existing static `discover_libraries(...)` call:
  if `use_browser` and `is_playwright_available()`, call
  `discover_libraries_via_browser(target, signatures)`, merge results
  de-duplicating by `f"{lib['name']}@{lib['version']}"` before proceeding to
  the CVE-lookup loop (so no duplicate CVE alerts for the same lib@version
  found by both methods).
- Add `--use-browser` to `build_parser()`.
- Update the dry-run `checks` list to mention browser-based discovery when
  enabled.

**Dependencies:** Task 2, Task 3 (for the `session_override` pattern
precedent -- not a hard code dependency, just do it in this order).
**Complexity:** S-M
**New deps:** none.

### Task 5: `prompt_injection.py` — JS-rendered chat widget detection
**Files to modify:** `C:\Users\User\Desktop\pen\modules\prompt_injection.py`

**What to implement:**
- Add `use_browser: bool = False` and `session_override: requests.Session | None = None`
  to `run_scan()`. Session line becomes
  `session = session_override or get_session()`.
- New function:
  ```python
  def detect_llm_features_via_browser(
      target: str, sigs: dict[str, list[str]],
  ) -> list[dict[str, str]]:
      """Render target with BrowserSession (wait_until='networkidle',
      extra_wait_ms=2000 -- chat widgets often lazy-load), run the SAME
      widget_scripts / dom_selectors / text_patterns matching logic against
      RenderedPage.html that detect_llm_features() already uses against
      static HTML, PLUS check RenderedPage.requests for any URL containing
      a widget_scripts fragment (catches widgets injected via JS that never
      appear as a literal <script src> in the DOM, e.g. loaded via
      dynamic script injection). Returns list[dict] in the same
      {"type","url","evidence"} shape as detect_llm_features."""
  ```
  To avoid duplicating the selector/text-matching code, extract the
  static-HTML-matching inner logic of `detect_llm_features` (the block from
  "Widget script detection" through "Meta tag / header detection") into a
  small private helper `_match_signatures_in_html(html: str, headers: dict,
  sigs: dict, add_fn: Callable) -> None` that both the static path and the
  new browser path call with their own `_add` closure.
- In `run_scan`, when `use_browser` and playwright available, merge the
  browser-detected features into `features` before the existing dedup-by-set
  logic (features already dedupes via the `seen` set keyed on
  `(feat_type, url, evidence)` -- reuse it, don't reinvent).
- Add `--use-browser` CLI flag.

**Dependencies:** Task 2.
**Complexity:** M
**New deps:** none.

---

## Phase 2 — CSRF token handling (Gap 2)

### Task 6: Shared form/CSRF helpers in `modules/common.py`
**Files to modify:** `C:\Users\User\Desktop\pen\modules\common.py`
**Files to modify (promote a private helper, no behavior change):**
`C:\Users\User\Desktop\pen\modules\auth_test.py`

**What to implement in `common.py`:**
```python
def extract_form_fields(form_element: Any) -> list[dict[str, str]]:
    """Moved verbatim from modules.auth_test._extract_form_fields."""

def extract_meta_csrf_token(html: str) -> str | None:
    """Look for <meta name="csrf-token" content="...">  or
    <meta name="csrf-param"/"csrf_token"> (Rails/Laravel/Django-style).
    Returns the content value or None."""

def find_matching_form(html: str, page_url: str, action_url: str, method: str) -> Any | None:
    """Parse html, return the bs4 <form> element whose resolved action
    (via resolve_url(page_url, form['action'])) equals action_url and whose
    method.upper() equals method. Returns None if no match (page structure
    changed, form removed, etc.) -- callers must handle None gracefully."""

def refresh_form_fields(
    session: Any, page_url: str, action_url: str, method: str, timeout: int = 15,
) -> tuple[list[dict[str, str]] | None, str | None]:
    """Re-GET page_url, locate the matching form via find_matching_form,
    return (fresh_fields, meta_csrf_token). fresh_fields is None if the
    page could not be fetched or the form could not be relocated (caller
    must fall back to its previously-cached fields in that case -- this is
    a network/parsing failure, not a security finding)."""
```
- Update `modules/auth_test.py`: delete its local `_extract_form_fields`
  function body and replace call sites with the imported
  `common.extract_form_fields`. Update the import block at the top of
  `auth_test.py` to add `extract_form_fields` (and later
  `refresh_form_fields`, `extract_meta_csrf_token`) to the existing
  `from modules.common import (...)` tuple.
- Add `tests/test_common.py` cases for `extract_meta_csrf_token`,
  `find_matching_form`, `refresh_form_fields` (using `FakeSession` +
  `sample_login_html` fixture from Task 1, extended with a second fixture
  `sample_login_html_rotated_csrf` whose token value differs from the first
  fetch, to prove refresh picks up the new value).

**Dependencies:** Task 1 (test fixtures).
**Complexity:** S-M
**New deps:** none.

### Task 7: `auth_test.py` — CSRF-aware active submissions
**Files to modify:** `C:\Users\User\Desktop\pen\modules\auth_test.py`

**What to implement:**
- Add `csrf_aware: bool = True` keyword-only parameter to `run_scan()`
  (default True = safer/better behavior out of the box, but overridable to
  restore old raw-speed behavior for targets known not to use per-request
  CSRF tokens).
- In `test_password_policy`, `test_default_credentials`, and
  `test_brute_force_protection`: before building the `data` dict for EACH
  submission attempt (i.e. inside the per-credential / per-attempt loop,
  not once before the loop), when `csrf_aware=True`:
  1. Call `refresh_form_fields(session, ep["url"], ep["action"], ep["method"], timeout=timeout)`.
  2. If it returns fresh fields, use them to rebuild the hidden-field
     portion of `data` (username/password field names stay the same --
     only hidden fields, which include rotating CSRF tokens, get replaced).
     If it returns `None` (fetch/parse failure), fall back to the
     originally-cached `ep["fields"]`/`form["fields"]` and log via
     `logger.debug` -- do not abort the test.
  3. If `extract_meta_csrf_token` finds a token on the refreshed page,
     inject it as both `X-CSRF-Token` and `X-XSRF-TOKEN` request headers
     on that single request via `session.post(..., headers={...})`
     (covers Rails/Laravel/Angular XSRF-cookie-to-header conventions)
     without mutating `session.headers` permanently (pass a per-call
     `headers=` kwarg, since other endpoints must not inherit this header).
  - **Rate limiting note:** this doubles the HTTP request count per attempt
    (one GET to refresh + one POST to submit). Do not add extra
    `time.sleep()` beyond what's already there -- the existing sleeps
    (`time.sleep(1)`, `time.sleep(1.5)`) already throttle the POST; add a
    short `time.sleep(0.3)` after the refresh GET only, to avoid bursting
    two rapid requests back to back.
- Update the `run_scan()` dry-run `checks` list to include
  `"CSRF token refresh before each active submission (csrf_aware=True)"`
  when applicable, and add `--no-csrf-aware` (store_false, dest=`csrf_aware`)
  to `_build_cli_parser()`.
- **New passive alert** (no `--confirm` needed): add a function
  `check_csrf_protection(session, endpoints, timeout=15) -> list[dict]`
  that, for each discovered login endpoint, fetches the page twice a few
  seconds apart and compares the hidden CSRF-looking field's value (any
  hidden field whose name matches `re.compile(r"csrf|token|_token|authenticity", re.I)`).
  If the value is IDENTICAL across both fetches (and the field exists),
  emit an **Informational** `make_alert(risk="Informational", alert_name="Static/Non-Rotating CSRF Token Detected", ...)` -- this is a genuine, valuable passive finding (non-rotating tokens are weaker) and does not require active testing. If the value differs, no alert (token rotation working as expected). Call this from
  `run_scan()` in the passive section (always runs, before the `--confirm`
  gate), alongside the existing `check_cleartext_login` call.
- **DORA mapping note:** verify the new alert name `"Static/Non-Rotating CSRF Token Detected"`
  contains the substring `"csrf"` (it does) so it maps correctly to `24_1_a` via the
  existing `_DORA_KEYWORD_MAP`. No code change required in `zap_scan.py` for this
  specific alert -- verify with a test instead (`tests/test_zap_scan_report.py`:
  `test_csrf_alert_maps_to_24_1_a`).

**Dependencies:** Task 6.
**Complexity:** M
**New deps:** none.

---

## Phase 3 — Authenticated scanning (Gap 3)

### Task 8: `modules/authenticated_scan.py` — login + authenticated crawl
**Files to create:** `C:\Users\User\Desktop\pen\modules\authenticated_scan.py`

**What to implement:**
```python
from __future__ import annotations
import argparse, re, time
from typing import Any
from urllib.parse import urljoin, urlparse

from modules.common import (
    make_alert, get_session, interactive_confirm, audit_log,
    print_dry_run, fetch_page, parse_html, is_same_origin, resolve_url,
    extract_form_fields, refresh_form_fields, extract_meta_csrf_token,
)
from modules.auth_test import (
    _has_password_field, _identify_field, _build_form_data,
    _PASSWORD_FIELD_NAMES, _USERNAME_FIELD_NAMES,
    _SUCCESS_INDICATORS, _response_contains,
)

def login_and_get_session(
    target: str, *, login_url: str | None = None,
    username: str | None = None, password: str | None = None,
    session_cookie: str | None = None, auth_header: str | None = None,
    timeout: int = 15,
) -> tuple[Any | None, str]:
    """Returns (authenticated_session_or_None, status_message).

    Three mutually exclusive auth strategies, checked in this priority
    order:
    1. session_cookie provided (format "name=value" or raw Cookie header
       string) -> build a session, set the cookie directly, GET login_url
       or target to verify it isn't redirected to a login page (heuristic:
       final response path doesn't contain 'login'/'signin'). No form
       submission at all -- this is just reusing an operator-supplied,
       already-authenticated session and requires no --confirm.
    2. auth_header provided (format "Header-Name: value") -> same idea,
       set as a persistent session header.
    3. username + password + login_url provided -> use
       auth_test.discover_login_endpoints-style single-page form discovery
       against login_url (reuse _has_password_field/_identify_field/
       extract_form_fields), then submit via CSRF-aware POST (reuse
       refresh_form_fields + extract_meta_csrf_token exactly like
       Task 7's pattern), and verify success via _response_contains(...,
       _SUCCESS_INDICATORS) OR a session/auth cookie appearing in
       resp.cookies OR redirect to a non-login path.
    If none of the three input sets is provided, returns (None, "no
    credentials supplied").
    If login attempt fails validation, returns (None, "<reason>") --
    caller must not proceed with an unauthenticated session silently.
    """

def crawl_authenticated(
    session: Any, target: str, *, seed_paths: list[str] | None = None,
    max_pages: int = 50, timeout: int = 15,
) -> list[dict[str, Any]]:
    """Same-origin breadth-first crawl using the authenticated session.
    Starts from target plus any seed_paths (resolved against target).
    Stdlib/bs4 only (no Playwright dependency here -- keep this module
    lean; JS-rendered authenticated crawling is an explicit non-goal for
    this task, documented as a known limitation in the module docstring).
    Hard caps: max_pages (default 50, clamp to a _MAX_PAGES_CAP = 200
    like auth_test's _MAX_ATTEMPTS_CAP pattern), and a same-origin check
    via is_same_origin() on every discovered <a href>. Skips
    non-HTML content-types and anchors matching /logout|signout/i (never
    crawl the logout link -- would invalidate the session mid-scan).
    Returns list of {"url": str, "status": int, "title": str}.
    """
```
- Add `--auth-username`, `--auth-password`, `--auth-login-url`,
  `--session-cookie`, `--auth-header`, `--max-pages`, `--dry-run` to a new
  `build_parser()` + `main()` CLI in this file, following the exact
  structure/print conventions of `ransomware_readiness.build_parser()`
  (`prog="authenticated_scan"`).
- `crawl_authenticated` alerts: for now it does not itself emit alerts (pure
  discovery); Task 9 adds the alert-producing checks on top of its output.

**Dependencies:** Task 6 (CSRF helpers), Task 1 (tests).
**Complexity:** L
**New deps:** none.

### Task 9: `modules/authenticated_scan.py` — access-control & IDOR active probes + `run_scan`
**Files to modify:** `C:\Users\User\Desktop\pen\modules\authenticated_scan.py`

**What to implement:**
```python
_ID_PATTERN = re.compile(r"(/(?:users?|accounts?|orders?|invoices?|documents?|profiles?)/)(\\d+)\\b", re.I)

def test_horizontal_access_control(
    session: Any, unauth_session: Any, authenticated_urls: list[dict[str, Any]],
    timeout: int = 15,
) -> list[dict[str, Any]]:
    """For each authenticated_urls entry, re-request the SAME url with
    unauth_session (a fresh, cookie-less requests.Session from
    get_session()). If the unauthenticated request returns HTTP 200 with
    a body that is NOT a login/redirect page (reuse a small heuristic:
    response doesn't contain password-field markup and status==200 and
    len(body) is within 20% of the authenticated version's length), flag
    make_alert(risk="High", alert_name="Broken Access Control: Page Accessible Without Authentication", ...).
    This is inherently active in the sense it fires a second HTTP request
    per URL but it is NOT destructive (GET only, no data mutation) --
    still gate behind confirm to be conservative and consistent with the
    rest of the toolkit's stance on any automated multi-request probing
    beyond simple discovery."""

def test_idor_probe(
    session: Any, authenticated_urls: list[dict[str, Any]], timeout: int = 15,
) -> list[dict[str, Any]]:
    """For each authenticated URL whose path matches _ID_PATTERN, compute
    adjacent IDs (id-1 and id+1, floor at 0, skip if id-1 == id) and GET
    them with the SAME authenticated session. If a 200 response comes
    back with content clearly different from a 403/404-style page
    (heuristic: status==200 and no 'not found'/'forbidden'/'access denied'
    text and body length > 200 chars), flag
    make_alert(risk="High", alert_name="Potential Insecure Direct Object Reference (IDOR)", ...,
    cweid="639"). Rate-limit with time.sleep(1) between requests, cap
    total probes at _MAX_IDOR_PROBES = 30 (mirrors auth_test's
    _MAX_ATTEMPTS_CAP pattern) to bound active-test volume. This test
    MUST be gated: only runs when both confirm=True AND
    probe_access_control=True are passed to run_scan (mirrors the
    ransomware_readiness network_scan + confirm double-gate pattern
    exactly)."""

def run_scan(
    target: str, *, login_url: str | None = None, username: str | None = None,
    password: str | None = None, session_cookie: str | None = None,
    auth_header: str | None = None, seed_paths: list[str] | None = None,
    max_pages: int = 50, probe_access_control: bool = False,
    confirm: bool = False, timeout: int = 15, dry_run: bool = False,
) -> list[dict[str, Any]]:
    """Orchestration:
    1. dry_run -> print_dry_run and return [] (list intended steps,
       reflecting whether login creds / cookie / header were supplied).
    2. If no auth input supplied at all -> print a clear message and
       return [] (nothing to do -- do not error/exit, since this module
       is opt-in within run_modules.py).
    3. login_and_get_session(...). If it returns None -> emit ONE
       Informational alert 'Authenticated Scanning Skipped - Login Failed'
       with the status message in the description, and return.
    4. crawl_authenticated(...) -- always runs once logged in (no confirm
       needed, it's read-only GETs against pages the operator's own
       credentials can already reach).
    5. Emit one Informational alert summarising discovered authenticated
       pages ('Authenticated Attack Surface Discovered', evidence = URL
       count) -- do NOT emit one alert per URL (would flood the report);
       put the URL list in evidence (truncate to first 25 + '... and N more').
    6. If probe_access_control and confirm: interactive_confirm(...) with
       an explicit warning that this WILL touch other users'/records'
       data via ID manipulation and must only run with authorisation to
       test business-logic access controls, THEN call
       test_horizontal_access_control and test_idor_probe.
    7. audit_log at start/end mirroring other modules' AUTH_TEST_COMPLETE-
       style events."""
```
- Add `main()`/CLI wiring for the new flags (`--probe-access-control`)
  building on Task 8's parser.

**Dependencies:** Task 8.
**Complexity:** L
**New deps:** none.

### Task 10: `session_override` plumbing for post-auth reuse
**Files to modify:**
- `C:\Users\User\Desktop\pen\modules\ransomware_readiness.py`
- `C:\Users\User\Desktop\pen\modules\prompt_injection.py` (if not already
  done in Task 5 -- verify and only add if missing)
- `C:\Users\User\Desktop\pen\modules\supply_chain.py` (if not already done
  in Task 4 -- verify and only add if missing)

**What to implement:**
- `ransomware_readiness.run_scan()`: add `session_override: Any | None = None`
  keyword-only param; change `session = get_session(timeout=timeout)` to
  `session = session_override or get_session(timeout=timeout)`.
  No other logic changes -- this lets `run_modules.py` hand it an
  authenticated session so admin-panel/header/sensitive-file checks run
  against the logged-in attack surface too.
- Confirm `prompt_injection.py` and `supply_chain.py` already accept
  `session_override` from Tasks 4/5; if for any reason that was deferred,
  add it here identically.

**Dependencies:** Task 9.
**Complexity:** S
**New deps:** none.

### Task 11: Wire `authenticated` module into `run_modules.py` and `assess.py`
**Files to modify:**
- `C:\Users\User\Desktop\pen\run_modules.py`
- `C:\Users\User\Desktop\pen\assess.py`

**What to implement in `run_modules.py`:**
- `from modules import auth_test, supply_chain, prompt_injection, ransomware_readiness, authenticated_scan`
- `ALL_MODULES = ("auth", "supply-chain", "prompt-injection", "ransomware", "authenticated")`
  -- **do not** add `"authenticated"` to `_ACTIVE_MODULES`; its own internal
  `probe_access_control + confirm` double-gate (Task 9) is the enforcement
  point, matching how `ransomware`'s `network_scan` is handled today (it's
  in `ALL_MODULES` but the confirm requirement is conditional on
  `--network-scan`, driven by the `main()`-level check `needs_confirm = ... or args.network_scan`).
  Mirror that exact pattern: extend the `needs_confirm` computation in
  `main()` to also be `True` when `args.probe_access_control` is set.
- In `_run_module()`, add the `"authenticated"` dispatch branch forwarding
  all auth-related extra_args.
- Add CLI flags to `build_parser()`: `--auth-username`, `--auth-password`,
  `--auth-login-url`, `--session-cookie`, `--auth-header`, `--max-pages`
  (default 50), `--probe-access-control` (store_true). Add all of these to
  the `extra_args` dict built in `main()`.
- **Security note to implement literally**: `--auth-password` on the CLI
  puts a secret in shell history/process list. Add a note in `--help` text
  (`help="Password for authenticated scanning login. Prefer setting AUTH_PASSWORD env var instead."`)
  and in `main()`, if `--auth-password` not given, fall back to
  `os.environ.get("AUTH_PASSWORD", "")`, matching the existing
  `ZAP_API_KEY`/env-var convention already used elsewhere in this codebase.

**What to implement in `assess.py`:**
- Extend the `--custom-modules` `choices` list to include `"authenticated"`.
- Add the same new flags and forward them into the
  `run_selected_modules(..., extra_args={...})` call's `extra_args` dict.

**Dependencies:** Task 9, Task 10.
**Complexity:** M
**New deps:** none.

---

## Phase 4 — SSL/TLS configuration testing (Gap 4)

### Task 12: `modules/tls_check.py`
**Files to create:** `C:\Users\User\Desktop\pen\modules\tls_check.py`

**What to implement (stdlib `ssl`/`socket` only -- no new dependency):**
```python
from __future__ import annotations
import argparse, socket, ssl, datetime as dt
from typing import Any
from urllib.parse import urlparse

from modules.common import make_alert, audit_log, print_dry_run

_WEAK_TLS_VERSIONS = ("TLSv1", "TLSv1.1")
_WEAK_CIPHER_STRINGS = ("RC4", "DES-CBC3-SHA", "NULL", "EXPORT", "MD5", "aNULL", "eNULL")
_CERT_EXPIRY_WARN_DAYS = 30
```

Functions to implement:
- `_get_host_port(target: str) -> tuple[str, int, bool]` — returns (host, port, is_https)
- `check_certificate(host, port, timeout=10) -> dict[str, Any]` — verified + unverified TLS connection attempt, returns cert details, trust errors, cipher info
- `build_cert_alerts(host, port, target_url, cert_result) -> list[dict]` — produces alerts for: untrusted/self-signed (High, cweid=295), expired (Critical, cweid=298), nearing expiry (Medium), not yet valid (High), hostname mismatch (High, cweid=297)
- `check_protocol_versions(host, port, timeout=10) -> dict[str, str]` — tests each TLS version (1.0, 1.1, 1.2, 1.3) independently using min/max version pinning
- `build_protocol_alerts(target_url, version_status) -> list[dict]` — flags deprecated TLS 1.0/1.1 if supported (High, cweid=326)
- `check_weak_ciphers(host, port, timeout=10) -> list[str]` — tests each weak cipher string
- `build_cipher_alerts(target_url, weak_ciphers) -> list[dict]` — flags weak ciphers (High, cweid=327)
- `check_hsts(headers) -> list[dict]` — HSTS presence/configuration (distinct alert names from ransomware_readiness to avoid report confusion)
- `run_scan(target, *, timeout=10, dry_run=False, session_override=None) -> list[dict]` — orchestrates all checks, fully passive (no --confirm needed)

**Critical implementation note:** Every `ssl`/`socket` call site needs its own
try/except returning a degraded-but-non-fatal result. No single check failure
should crash the module run.

**Dependencies:** Task 1 (tests).
**Complexity:** L
**New deps:** none.

### Task 13: Wire `tls` module + DORA keyword/category updates
**Files to modify:**
- `C:\Users\User\Desktop\pen\run_modules.py`
- `C:\Users\User\Desktop\pen\assess.py`
- `C:\Users\User\Desktop\pen\zap_scan.py`

**What to implement:**
- `run_modules.py`: add `"tls"` to `ALL_MODULES` (passive, not in `_ACTIVE_MODULES`); add dispatch branch.
- `assess.py`: add `"tls"` to `--custom-modules` choices.
- `zap_scan.py` `_DORA_KEYWORD_MAP`: add TLS-related keyword tuple mapping to `"9_4"`:
  ```python
  (("tls certificate", "certificate nearing expiry", "expired tls certificate",
    "certificate not yet valid", "hostname mismatch", "self-signed",
    "untrusted", "deprecated tls protocol", "weak tls cipher",
    "hsts not enabled", "hsts max-age", "includesubdomains"), "9_4"),
  ```
- Add regression tests asserting each new TLS alert name maps correctly.

**Dependencies:** Task 12.
**Complexity:** S-M
**New deps:** none.

---

## Phase 5 — API schema discovery (Gap 5)

### Task 14: Promote helpers to `common.py` + OpenAPI/JS endpoint discovery
**Files to modify:**
- `C:\Users\User\Desktop\pen\modules\common.py`
- `C:\Users\User\Desktop\pen\modules\supply_chain.py`
- `C:\Users\User\Desktop\pen\modules\auth_test.py`
**Files to create:**
- `C:\Users\User\Desktop\pen\modules\api_discovery.py`
- `C:\Users\User\Desktop\pen\wordlists\api_spec_paths.txt`

**What to implement:**
- Promote `auth_test._load_lines` to `common.load_lines(path) -> list[str]`; update all call sites.
- Promote `supply_chain._extract_script_sources` to `common.extract_script_sources`; update all call sites.
- `wordlists/api_spec_paths.txt`: 14 common OpenAPI/Swagger spec paths.
- `modules/api_discovery.py` with:
  - `discover_openapi_spec(session, target, timeout) -> tuple[dict | None, str]`
  - `parse_openapi_endpoints(spec) -> list[dict]` — walks OpenAPI 3.x and Swagger 2.0 specs defensively
  - `discover_endpoints_from_js(session, target, html, timeout) -> list[str]` — regex extraction of `/api/...` literals from same-origin JS, cap at 25 scripts
  - `get_discovered_endpoints(target, *, timeout, session_override) -> list[dict]` — public entry point returning raw endpoint list for cross-module reuse (Task 16)
  - `run_scan(target, *, timeout, dry_run, session_override) -> list[dict]` — wraps discovery results as alerts (one per category, not one per endpoint)

**Dependencies:** Task 4, Task 1.
**Complexity:** L
**New deps:** none (pyyaml already required).

### Task 15: GraphQL introspection
**Files to modify:** `C:\Users\User\Desktop\pen\modules\api_discovery.py`
**Files to create:** `C:\Users\User\Desktop\pen\wordlists\graphql_paths.txt`

**What to implement:**
- `wordlists/graphql_paths.txt`: 6 common GraphQL endpoint paths.
- `test_graphql_introspection(session, target, timeout) -> list[dict]` — POST introspection query, emit Medium alert if schema returned, escalate to High if mutations are discoverable.
- Wire into `run_scan()` and dry-run checks list.
- Add CLI (`build_parser()`/`main()`).

**Dependencies:** Task 14.
**Complexity:** M
**New deps:** none.

### Task 16: `prompt_injection.py` — schema-aware payload construction
**Files to modify:** `C:\Users\User\Desktop\pen\modules\prompt_injection.py`

**What to implement:**
- `_build_payload_from_schema(schema, message) -> dict | None` — inspects OpenAPI requestBody schema to construct correctly-shaped JSON payloads instead of blind-firing.
- Modify `_send_chat_payload()` to accept `schema_hint` and try the schema-derived payload FIRST before falling back to the existing blind list.
- Add `use_api_discovery: bool = False` to `run_scan()` — when True, calls `api_discovery.get_discovered_endpoints()` and feeds results into `detect_llm_features(known_endpoints=...)`.
- Add `--use-api-discovery` CLI flag.

**Dependencies:** Task 15.
**Complexity:** M
**New deps:** none.

### Task 17: Wire `api-discovery` module + final DORA keyword/category updates
**Files to modify:**
- `C:\Users\User\Desktop\pen\run_modules.py`
- `C:\Users\User\Desktop\pen\assess.py`
- `C:\Users\User\Desktop\pen\zap_scan.py`

**What to implement:**
- Wire `"api-discovery"` into `ALL_MODULES` and dispatch.
- Add `--use-browser` and `--use-api-discovery` as global flags in `run_modules.py` and `assess.py`.
- Add DORA keyword mappings for API/IDOR/access-control alert names.
- Add regression tests for all new alert-to-article mappings.

**Dependencies:** Task 16, Task 13, Task 11.
**Complexity:** M
**New deps:** none.

---

## Phase 6 — Final integration, docs, dependency files

### Task 18: `requirements.txt` / `requirements-dev.txt` finalization + `README.md`
**Files to modify:**
- `C:\Users\User\Desktop\pen\requirements.txt`
- `C:\Users\User\Desktop\pen\requirements-dev.txt`
- `C:\Users\User\Desktop\pen\README.md`

**What to implement:**
- Confirm final dependency pins.
- Document the 3 new modules (`tls`, `api-discovery`, `authenticated`).
- Document `--use-browser`, `--use-api-discovery`, `AUTH_PASSWORD` env var.
- Document Playwright install step.
- "Known Limitations" section: no JS-rendered authenticated crawling, no full X.509 extension parsing without `cryptography`, no GraphQL mutation fuzzing.

**Dependencies:** all prior tasks.
**Complexity:** S
**New deps:** none.

---

## Phase 7 — Test coverage completion (Gap 6, part 2)

### Task 19: Tests for CSRF logic, authenticated_scan, browser_render fallback paths
**Files to create/modify:**
- `C:\Users\User\Desktop\pen\tests\test_auth_test.py` (extend)
- `C:\Users\User\Desktop\pen\tests\test_authenticated_scan.py` (new)
- `C:\Users\User\Desktop\pen\tests\test_browser_render.py` (new/extend)

**What to implement:**
- CSRF token refresh ordering tests (assert FakeSession call count/order).
- `check_csrf_protection` static vs rotating token tests.
- `login_and_get_session` for all three auth strategies.
- `crawl_authenticated` max_pages cap and logout-link avoidance.
- `test_idor_probe` adjacent ID computation and probe cap.
- Playwright fallback tests: verify `use_browser=True` with unavailable Playwright produces identical results to `use_browser=False`.

**Dependencies:** Tasks 2-11.
**Complexity:** M
**New deps:** none.

### Task 20: Full suite run, dispatch integration tests, cleanup
**Files to create/modify:**
- `C:\Users\User\Desktop\pen\tests\test_run_modules_dispatch.py` (new)

**What to implement:**
- For each of the 7 entries in the final `ALL_MODULES`, monkeypatch `run_scan` to a stub, invoke `_run_module()`, assert correct kwargs forwarding.
- Run `pytest -q` for the whole repo, fix any failures.
- Run `python -m py_compile` across every `.py` file.
- Dry-run each CLI entry point to confirm argparse wiring.

**Dependencies:** all prior tasks.
**Complexity:** M
**New deps:** none.

---

## Summary table

| # | Task | Gap | Complexity | New files | Key modified files |
|---|------|-----|------------|-----------|---------------------|
| 1 | pytest harness + baseline tests | 6 | M | requirements-dev.txt, pytest.ini, conftest.py, tests/* | -- |
| 2 | browser_render.py | 1 | M | modules/browser_render.py | requirements.txt |
| 3 | auth_test.py SPA discovery | 1 | M | -- | modules/auth_test.py |
| 4 | supply_chain.py dynamic scripts | 1 | S-M | -- | modules/supply_chain.py |
| 5 | prompt_injection.py JS widgets | 1 | M | -- | modules/prompt_injection.py |
| 6 | common.py CSRF helpers | 2 | S-M | -- | modules/common.py, modules/auth_test.py |
| 7 | auth_test.py CSRF-aware submits | 2 | M | -- | modules/auth_test.py |
| 8 | authenticated_scan.py login+crawl | 3 | L | modules/authenticated_scan.py | -- |
| 9 | authenticated_scan.py IDOR/ACL | 3 | L | -- | modules/authenticated_scan.py |
| 10 | session_override plumbing | 3 | S | -- | modules/ransomware_readiness.py |
| 11 | wire authenticated module | 3 | M | -- | run_modules.py, assess.py |
| 12 | tls_check.py | 4 | L | modules/tls_check.py | -- |
| 13 | wire tls + DORA mapping | 4 | S-M | -- | run_modules.py, assess.py, zap_scan.py |
| 14 | common helpers + api_discovery.py | 5 | L | modules/api_discovery.py, wordlists/api_spec_paths.txt | modules/common.py, modules/supply_chain.py |
| 15 | GraphQL introspection | 5 | M | wordlists/graphql_paths.txt | modules/api_discovery.py |
| 16 | prompt_injection schema-aware | 5 | M | -- | modules/prompt_injection.py |
| 17 | wire api-discovery + DORA mapping | 5 | M | -- | run_modules.py, assess.py, zap_scan.py |
| 18 | deps/README finalization | -- | S | -- | requirements.txt, README.md |
| 19 | CSRF/auth/browser tests | 6 | M | tests/* | -- |
| 20 | full suite + dispatch integration | 6 | M | tests/test_run_modules_dispatch.py | fix-ups as needed |
