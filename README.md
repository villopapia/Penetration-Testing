# ZAP Scan Orchestrator

CLI tool that drives [OWASP ZAP](https://www.zaproxy.org/) scans via its Python API and produces structured vulnerability reports.

## Prerequisites

### 1. Install OWASP ZAP

Download from <https://www.zaproxy.org/download/> or install via a package manager:

```bash
# macOS
brew install --cask zap

# Linux (snap)
sudo snap install zaproxy --classic

# Windows — use the installer from the download page
```

### 2. Start ZAP in daemon mode

```bash
# Linux / macOS
zap.sh -daemon -port 8080 -config api.key=your-api-key-here

# Windows
zap.bat -daemon -port 8080 -config api.key=your-api-key-here
```

To find or set your API key, open ZAP's GUI → *Tools → Options → API* and copy the key shown there. You can also disable the key requirement for local-only use with `-config api.disablekey=true` (not recommended in shared environments).

### 3. Install the Python client

```bash
pip install zaproxy
```

## Usage

### Baseline scan (passive only — safe, no attack payloads)

```bash
python zap_scan.py --target https://staging.example.com --api-key YOUR_KEY
```

This spiders the target to discover pages, then waits for ZAP's passive scanner to flag issues. No attack traffic is sent.

### Full scan (spider + active attacks)

```bash
python zap_scan.py \
  --target https://staging.example.com \
  --api-key YOUR_KEY \
  --scan-type full \
  --confirm
```

The `--confirm` flag is mandatory for active scans. You will also be prompted to type `yes` at the terminal before the scan begins.

### API scan (OpenAPI / Swagger spec)

```bash
python zap_scan.py \
  --target https://staging.example.com \
  --api-key YOUR_KEY \
  --scan-type api \
  --openapi-spec openapi.json \
  --confirm
```

ZAP imports the spec, discovers the defined endpoints, then runs an active scan against them.

### Report formats

```bash
# Markdown (default)
python zap_scan.py --target https://staging.example.com --format md

# JSON (machine-readable)
python zap_scan.py --target https://staging.example.com --format json

# HTML (styled report with section-based template)
python zap_scan.py --target https://staging.example.com --format html
```

Reports follow a fixed 7-section template:

1. **Executive Summary** — scope, methodology, findings-at-a-glance, priority recommendations
2. **Risk Categorization Methodology** — severity definitions
3. **Technical Findings** — detailed findings grouped by severity
4. **Recommendations Summary** — prioritised table with quick wins, structural, and process recommendations
5. **Testing Scope & Methodology** — tools, test types, exclusions
6. **Regulatory Alignment — DORA** (conditional, see `--regulatory-framework`)
7. **Disclaimer**

### Manual findings

Merge manual penetration test findings with automated ZAP results into one combined report:

```bash
python zap_scan.py \
  --target https://staging.example.com \
  --api-key YOUR_KEY \
  --manual-findings manual_findings.json
```

The manual findings file is a JSON array of finding objects. See `findings_schema_example.json` for the expected schema:

```json
[
  {
    "severity": "High",
    "title": "Finding title",
    "category": "Access Control",
    "description": "Technical description...",
    "affected_component": "GET /api/v1/resource",
    "proof_of_concept": "Steps to reproduce...",
    "recommendation": "How to fix...",
    "business_impact": "Optional business impact statement"
  }
]
```

Findings from both sources are merged, deduplicated (by title + category), sorted by severity, and tagged with their source (`[Automated]` or `[Manual]`).

### Business context

Provide category-to-business-impact mappings so the report auto-fills business impact statements for each finding:

```bash
python zap_scan.py \
  --target https://staging.example.com \
  --api-key YOUR_KEY \
  --business-context business_context.json
```

Business context file format (JSON or YAML):

```json
{
  "category_impacts": {
    "Cookie Security": "Weak cookie configuration could allow session hijacking...",
    "Content Security Policy": "Missing CSP headers increase XSS risk..."
  }
}
```

### DORA regulatory alignment

Include a DORA regulatory mapping section (Section 6) that maps findings to ICT risk categories:

```bash
python zap_scan.py \
  --target https://staging.example.com \
  --api-key YOUR_KEY \
  --regulatory-framework dora
```

### Excluding URLs from scan scope

Document URL patterns that were excluded from scanning:

```bash
python zap_scan.py \
  --target https://staging.example.com \
  --api-key YOUR_KEY \
  --exclude-urls "*/admin/*" "*/health" "*/metrics"
```

### Dry run

```bash
python zap_scan.py --target https://staging.example.com --scan-type full --confirm --dry-run
```

Prints the steps that *would* execute without contacting ZAP.

### Additional options

| Flag | Default | Description |
|------|---------|-------------|
| `--zap-url` | `http://localhost:8080` | Base URL where ZAP is listening |
| `--api-key` | `ZAP_API_KEY` env var | ZAP API key |
| `--timeout` | `3600` | Max scan duration in seconds |
| `--output` | `zap_report_<timestamp>.<ext>` | Output file path |
| `--manual-findings` | None | Path to JSON file with manual test findings |
| `--regulatory-framework` | `none` | `none` or `dora` — controls DORA section inclusion |
| `--business-context` | None | Path to JSON/YAML mapping categories to business impact |
| `--exclude-urls` | None | URL patterns excluded from scanning |
| `--entity-name` | None | Name of the regulated entity |
| `--entity-lei` | None | LEI or national registration number |
| `--assessor-name` | Current user | Assessor name |
| `--assessment-date` | Today | Assessment date (ISO format) |

## Audit log

Every scan start and end is logged to `scan_audit.log` in the working directory with timestamps, target, scan type, and the OS user who ran it.

## Safety guardrails

- Active scans (`full`, `api`) require both `--confirm` and a typed `yes` at the terminal.
- The `--dry-run` flag lets you inspect the plan before running.
- The audit log records all scan activity for accountability.
- Only OWASP ZAP's built-in scan engine is used — no custom payloads or functionality outside ZAP's API.
