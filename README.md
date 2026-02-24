# Project Flaw

**An intelligent CLI tool for detecting, prioritizing, and analyzing critical software vulnerabilities in containerized environments.**

Flaw goes beyond standard vulnerability scanning. Instead of dumping hundreds of CVEs, it provides a **Context-Aware Risk Score** that helps you focus on what actually matters — vulnerabilities that are exploitable *right now*.

## Why Flaw?

Traditional scanners like Trivy, Grype, or Snyk output a flat list sorted by CVSS.
CVSS alone is a poor predictor of real-world exploitation:

| Metric       | What it tells you                                               |
|--------------|-----------------------------------------------------------------|
| **CVSS**     | Theoretical severity (static, never changes)                    |
| **EPSS**     | Probability of exploitation in the next 30 days (updated daily) |
| **CISA KEV** | Already actively exploited in the wild (confirmed)              |

Flaw combines all three into a single **Risk Score (0–100)** so you can prioritize effectively.

> **Status:** Early development.

## Quick Start

```bash
# Scan an image — get a prioritized table
flaw scan nginx:1.24

# JSON output for piping
flaw scan nginx:1.24 --format json | jq '.vulnerabilities[:3]'

# Save report to file
flaw scan nginx:1.24 -o report.json

# Show only top 5 riskiest vulnerabilities
flaw scan nginx:1.24 --top 5

# CI mode — fail pipeline if any CVE risk > 70
flaw scan nginx:1.24 --threshold 70

# Scan image + analyze its Dockerfile
flaw scan nginx:1.24 --dockerfile ./Dockerfile

# Lint a Dockerfile without scanning an image
flaw lint ./Dockerfile
```

## Commands

```text
Usage: flaw [OPTIONS] <COMMAND>

Commands:
  scan      Scan a container image for vulnerabilities and prioritize risks
  lint      Analyze a Dockerfile for security misconfigurations
  cache     Manage local vulnerability databases (EPSS, KEV)
  version   Display the flaw version

Global options:
  -q, --quiet       Suppress all output except errors
  -v, --verbose     Show detailed output with timings
      --offline     Disable network access, use cached data only
      --no-cache    Skip cache, use temporary data
  -h, --help        Display help
  -V, --version     Display version
```

`flaw scan`

```bash
flaw scan [OPTIONS] <IMAGE>

Options:
      --dockerfile <PATH>    Also analyze a Dockerfile alongside the image
      --top <N>              Show only top N vulnerabilities by risk score
      --no-enrich            Skip EPSS/KEV enrichment (CVSS-only scoring)
  -f, --format <FORMAT>      Output format: table (default), json
  -o, --output <FILE>        Write JSON report to file
  -t, --threshold <SCORE>    Exit code 1 if any CVE exceeds the given risk score
```

`flaw lint`

```bash
flaw lint [OPTIONS] [PATH]

Arguments:
  [PATH]    Path to Dockerfile [default: ./Dockerfile]

Options:
  -f, --format <FORMAT>    Output format: table (default), json
  -o, --output <FILE>      Write JSON report to file
      --ci                 CI mode: exit 1 if any HIGH severity issue found
```

`flaw cache`

```bash
flaw cache <COMMAND>

Commands:
  update    Download or refresh EPSS and KEV databases
  status    Show cache age, size, and entry counts
  clean     Remove all cached data
  dir       Print the cache directory path
```

## Example output

```text
╭──────────────────────────────────────────────────────────╮
│  Flaw — nginx:1.24                                       │
│  Scanned in 5.3s | 42 CVEs | Max Risk: 87.3              │
╰──────────────────────────────────────────────────────────╯

 # │ CVE            │ Pkg      │ CVSS │ EPSS   │ KEV │ Risk  │
───┼────────────────┼──────────┼──────┼────────┼─────┼───────┤
 1 │ CVE-2023-44487 │ nghttp2  │  7.5 │ 0.9214 │  ●  │  87.3 │
 2 │ CVE-2024-6119  │ openssl  │  5.5 │ 0.0023 │     │  34.1 │
 3 │ CVE-2024-0001  │ curl     │  4.3 │ 0.0010 │     │  12.5 │
   │ ...            │          │      │        │     │       │

 Dockerfile Issues (3):
   HIGH  DF-001  No USER directive — container runs as root
   MED   DF-003  Base image uses :latest tag
   INFO  DF-006  No HEALTHCHECK defined

 Summary:
   Critical: 1  High: 5  Medium: 36
   In CISA KEV: 1  Has public exploit: 2
```

## Risk Score

The Risk Score (0–100) is computed from multiple signals:

| Signal          | Weight | Source            |
|-----------------|--------|-------------------|
| CVSS v3         | 30%    | NVD / vendor      | 
| EPSS            | 35%    | FIRST.org         |
| CISA KEV        | 25%    | CISA              |
| Public Exploit  | 10%    | Exploit databases |

A trained ML model (XGBoost, pure-Python inference) can optionally replace the weighted formula for higher accuracy.

## CI/CD Integration

### GitHub Actions

```yaml
- name: Scan for vulnerabilities
  run: flaw scan myapp:${{ github.sha }} --threshold 70
```

### GitLab CI

```yaml
security_scan:
  script:
    - flaw scan myapp:${CI_COMMIT_SHA} --threshold 70
```

Exit codes:

| Code | Meaning                                        |
|------|:-----------------------------------------------|
| 0    | Scan completed, no CVE exceeds threshold       | 
| 1    | At least one CVE exceeds threshold             |
| 2    | Error (Trivy not found, image not found, etc.) |

## Configuration

Settings are configurable via `flaw.toml` or environment variables (prefix `FLAW_`):

```toml
# ~/.config/flaw/flaw.toml

[scan]
risk_threshold = 70.0
trivy_timeout = 300

[cache]
ttl_hours = 24
```

```bash
# Or via environment variables
export FLAW_RISK_THRESHOLD=70.0
export FLAW_CACHE_TTL_HOURS=24
export FLAW_TRIVY_TIMEOUT=300
```

## Data Storage

Flaw follows the [XDG Base Directory Specification](https://specifications.freedesktop.org/basedir-spec/latest/):

| Path                   | Purpose                             |
|------------------------|:------------------------------------|
| `~/.config/flaw/`      | Configuration (`flaw.toml`)         | 
| `~/.local/share/flaw/` | EPSS/KEV database, ML model weights |
| `~/.cache/flaw/`       | Temporary cache                     |

## Architecture

```text
Image -> Trivy Scan -> Enrichment (EPSS + KEV) -> Risk Scoring -> Report
                              ↑                        ↑
                        SQLite Cache              Formula / ML
```

* Scanner layer: Trivy wrapper + Docker/Podman runtime detection
* Intelligence layer: EPSS + KEV enrichment, risk scoring
* Report layer: Rich terminal tables (stderr) + JSON (stdout/file)

## License

flaw is licensed under Apache License, Version 2.0, ([LICENSE](https://github.com/mikoavelli/flaw/blob/main/LICENSE) or https://www.apache.org/licenses/LICENSE-2.0)