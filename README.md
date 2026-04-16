<p align="center">
  <img src="https://img.shields.io/badge/%F0%9F%9B%A1%EF%B8%8F_CASCAVEL-Header_Guard-3B82F6?style=for-the-badge&labelColor=0D1117" />
</p>

<h1 align="center">🛡️ Cascavel Header Guard</h1>

<p align="center">
  <strong>HTTP Security Headers Analyzer for CI/CD Pipelines.</strong><br />
  <em>Audit any URL. Score from A+ to F. Block deploys with weak headers.</em>
</p>

<p align="center">
  <a href="https://github.com/marketplace/actions/cascavel-header-guard"><img src="https://img.shields.io/badge/GitHub%20Marketplace-Cascavel%20Header%20Guard-2ea44f?style=flat-square&logo=github" alt="Marketplace" /></a>
  <img src="https://img.shields.io/badge/headers-15+-7C3AED?style=flat-square" alt="15+ headers" />
  <img src="https://img.shields.io/badge/grading-A+_to_F-3B82F6?style=flat-square" alt="Grading" />
  <img src="https://img.shields.io/badge/config-zero-10B981?style=flat-square" alt="Zero config" />
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-EAB308?style=flat-square" alt="MIT" /></a>
  <a href="https://rettecnologia.org"><img src="https://img.shields.io/badge/by-RET%20Tecnologia-FF6B00?style=flat-square" alt="RET" /></a>
</p>

<br />

<p align="center">
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-why-header-guard">Why?</a> •
  <a href="#-headers-checked">Headers</a> •
  <a href="#-advanced-usage">Advanced</a> •
  <a href="#-grading-system">Grading</a> •
  <a href="#-inputs">Inputs</a>
</p>

---

## 🚀 Quick Start

```yaml
name: Security Headers
on: [push, pull_request]

jobs:
  headers:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: glferreira-devsecops/cascavel-header-guard@v1
        with:
          urls: 'https://your-app.com'
```

> Instantly audits **HSTS, CSP, X-Frame-Options, Permissions-Policy**, and 12+ more security headers. Blocks deploys that score below your threshold.

---

## 💡 Why Header Guard?

Missing security headers are among the **most common web vulnerabilities** and appear in every OWASP checklist. Yet most teams only discover them during penetration tests — after deployment.

**Header Guard catches them in CI/CD**, before code reaches production.

| Problem | Solution |
|:--------|:---------|
| Missing HSTS → MITM attacks | ✅ Detects and scores HSTS quality (max-age, preload) |
| No CSP → XSS exploitation | ✅ Flags unsafe-inline/unsafe-eval as score penalties |
| X-Powered-By leaks tech stack | ✅ Flags presence as a security issue |
| Server header reveals versions | ✅ Detects version disclosure patterns |
| Clickjacking via missing X-Frame-Options | ✅ Validates DENY/SAMEORIGIN values |
| No CORS isolation headers | ✅ Checks COOP, CORP, COEP headers |

---

## 📊 Grading System

Each URL receives a **score (0-100)** and a **letter grade**:

| Grade | Score | Meaning |
|:-----:|:-----:|:--------|
| 🏆 A+ | 95-100 | Exceptional — all headers present with optimal values |
| ✅ A | 80-94 | Strong — all critical headers, minor improvements possible |
| 🟢 B | 60-79 | Good — most important headers present |
| 🟡 C | 40-59 | Fair — several important headers missing |
| 🟠 D | 20-39 | Poor — critical headers missing |
| 🔴 F | 0-19 | Failing — most security headers absent |

**Scoring weights** reflect real-world impact:
- 🔴 Critical headers (HSTS, CSP, X-Content-Type): **10-15 points each**
- 🟠 High headers (X-Frame, Referrer-Policy, COOP): **5-8 points each**
- 🟡 Medium headers (Cache-Control, DNS Prefetch): **3-4 points each**
- **Bonuses**: HSTS preload (+5), strong CSP (+2)
- **Penalties**: CSP unsafe-eval (-5), server version leak (-1)

---

## 🔍 Headers Checked

### 🔴 Critical (blocks deploy if missing)

| Header | Points | What it prevents |
|:-------|:------:|:-----------------|
| `Strict-Transport-Security` | 15 | Man-in-the-middle attacks, SSL stripping |
| `Content-Security-Policy` | 15 | Cross-site scripting (XSS), code injection |
| `X-Content-Type-Options` | 10 | MIME-type sniffing attacks |

### 🟠 High

| Header | Points | What it prevents |
|:-------|:------:|:-----------------|
| `X-Frame-Options` | 8 | Clickjacking attacks |
| `Referrer-Policy` | 7 | Information leakage via referrer |
| `Permissions-Policy` | 7 | Unauthorized camera/mic/location access |
| `Cross-Origin-Opener-Policy` | 6 | Cross-origin window manipulation |
| `Cross-Origin-Resource-Policy` | 6 | Unauthorized resource loading |
| `Cross-Origin-Embedder-Policy` | 5 | Spectre-class side-channel attacks |
| `X-XSS-Protection` | 5 | Legacy XSS filter (compatibility) |

### 🟡 Medium

| Header | Points | Purpose |
|:-------|:------:|:--------|
| `Cache-Control` | 4 | Prevent caching of sensitive pages |
| `X-DNS-Prefetch-Control` | 3 | Prevent DNS-based tracking |
| `X-Download-Options` | 3 | Prevent IE auto-open downloads |
| `X-Permitted-Cross-Domain-Policies` | 3 | Block Adobe Flash cross-domain |

### ℹ️ Informational (reverse scoring)

| Header | Points | What we check |
|:-------|:------:|:--------------|
| `Server` | 2 | Should NOT reveal version numbers |
| `X-Powered-By` | 2 | Should NOT be present at all |

---

## 🔧 Advanced Usage

### Scan multiple endpoints

```yaml
- uses: glferreira-devsecops/cascavel-header-guard@v1
  with:
    urls: 'https://app.example.com,https://api.example.com,https://cdn.example.com'
    fail-score: '60'
```

### Strict mode for production

```yaml
- uses: glferreira-devsecops/cascavel-header-guard@v1
  with:
    urls: 'https://production.example.com'
    fail-on-missing-critical: 'true'
    fail-score: '80'
```

### Staging only (don't block pipeline)

```yaml
- uses: glferreira-devsecops/cascavel-header-guard@v1
  id: headers
  with:
    urls: 'https://staging.example.com'
    fail-on-missing-critical: 'false'
    fail-score: '0'

- name: Report score
  run: echo "Security score: ${{ steps.headers.outputs.total-score }}/100"
```

---

## ⚙️ Inputs

| Input | Description | Required | Default |
|:------|:------------|:--------:|:--------|
| `urls` | Comma-separated URLs to scan | **Yes** | — |
| `fail-score` | Minimum passing score (0-100) | No | `50` |
| `fail-on-missing-critical` | Fail if HSTS/CSP/X-Content-Type missing | No | `true` |
| `timeout` | HTTP request timeout in seconds | No | `10` |
| `follow-redirects` | Follow HTTP redirects | No | `true` |
| `user-agent` | Custom User-Agent string | No | `Cascavel-HeaderGuard/1.0` |

## 📤 Outputs

| Output | Description | Example |
|:-------|:------------|:--------|
| `total-score` | Average score across all URLs | `72` |
| `worst-score` | Lowest score | `58` |
| `missing-critical` | Missing critical header count | `1` |
| `report-path` | Path to JSON report | `.cascavel/headers-report.json` |

---

## 📊 Example Output

```
  ╔══════════════════════════════════════════════════╗
  ║  🛡️  CASCAVEL HEADER GUARD v1.0.0              ║
  ║  HTTP Security Headers Analyzer                  ║
  ║  RET Tecnologia · https://rettecnologia.org      ║
  ╚══════════════════════════════════════════════════╝

  🎯 Targets: 1 URL(s)
  ⏱️  Timeout: 10s
  📏 Min score: 50/100

  🔗 Scanning: https://your-app.com
  ────────────────────────────────────────────────────
  📡 HTTP Status: 200

  ✅ strict-transport-security: max-age=31536000; includeSubDomains; preload
  🔴 content-security-policy: MISSING [CRITICAL] — Prevents XSS
  ✅ x-content-type-options: nosniff
  ✅ x-frame-options: DENY
  🟠 referrer-policy: MISSING [HIGH] — Controls referrer info
  ✅ permissions-policy: camera=(), microphone=()
  🔴 x-powered-by: Express (REMOVE THIS — leaks technology)

  ────────────────────────────────────────────────────
  🟡 Score: 58/100 (Grade: C)
  📊 Present: 10 | Missing: 5 | Critical missing: 1
```

---

## 🔗 Cascavel Security Suite

| Action | Description | Status |
|:-------|:------------|:------:|
| [🐍 Secret Scanner](https://github.com/marketplace/actions/cascavel-secret-scanner) | Detect hardcoded credentials | ✅ Live |
| [🛡️ Header Guard](https://github.com/marketplace/actions/cascavel-header-guard) | HTTP security headers analysis | ✅ Live |
| [📦 Dependency Audit](https://github.com/marketplace/actions/cascavel-dependency-audit) | CVE scanning for dependencies | ✅ Live |

### Full security pipeline

```yaml
name: Cascavel Security Suite
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: glferreira-devsecops/cascavel-secret-scanner@v1
      - uses: glferreira-devsecops/cascavel-dependency-audit@v1
      - uses: glferreira-devsecops/cascavel-header-guard@v1
        with:
          urls: 'https://staging.your-app.com'
```

---

## 📄 License

[MIT](LICENSE) — free for personal and commercial use.

---

<p align="center">
  <a href="https://rettecnologia.org"><img src="https://img.shields.io/badge/RET%20Tecnologia-Software%20Engineering%20%C2%B7%20Cybersecurity-0D1117?style=for-the-badge&labelColor=FF6B00" /></a>
</p>

<p align="center">
  <sub>Built with ❤️ by <a href="https://github.com/glferreira-devsecops">Gabriel Ferreira</a> at <a href="https://rettecnologia.org">RET Tecnologia</a> · Brazil 🇧🇷</sub>
</p>
