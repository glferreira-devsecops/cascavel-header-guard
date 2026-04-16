<p align="center">
  <img src="https://img.shields.io/badge/🛡️_CASCAVEL-Header_Guard-0066FF?style=for-the-badge&labelColor=1a1a2e" />
</p>

<h1 align="center">Cascavel Header Guard</h1>
<h3 align="center">HTTP Security Headers Analyzer for CI/CD Pipelines</h3>

<p align="center">
  <a href="https://github.com/marketplace/actions/cascavel-header-guard"><img src="https://img.shields.io/badge/GitHub_Marketplace-Available-2ea44f?style=flat-square&logo=github" /></a>
  <img src="https://img.shields.io/badge/Headers-15+-blueviolet?style=flat-square" />
  <img src="https://img.shields.io/badge/Grading-A+_to_F-blue?style=flat-square" />
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-00D4FF?style=flat-square" /></a>
  <a href="https://rettecnologia.org"><img src="https://img.shields.io/badge/RET_Tecnologia-Open_Source-FF6B00?style=flat-square" /></a>
</p>

<p align="center">
  Audit HTTP security headers of any URL in your CI/CD pipeline.<br />
  Checks HSTS, CSP, X-Frame-Options, Permissions-Policy, and 15+ headers.<br />
  <strong>Scores each URL from 0-100 with letter grades (A+ to F).</strong>
</p>

---

## ⚡ Quick Start

```yaml
- uses: glferreira-devsecops/cascavel-header-guard@v1
  with:
    urls: 'https://your-app.com'
```

## 🎯 Features

- 🔍 **15+ security headers** checked with quality validation
- 📊 **Scoring system** (0-100) with letter grades (A+ to F)
- 🔴 **Critical header detection** — HSTS, CSP, X-Content-Type-Options
- 🧪 **Value quality analysis** — checks HSTS max-age, CSP unsafe-inline, etc.
- 📋 **JSON report** with per-URL breakdown
- 🛡️ **Server header audit** — flags version disclosure
- ⚡ **Multi-URL scanning** — scan multiple endpoints in one step

## 📖 Usage

### Scan multiple URLs

```yaml
- uses: glferreira-devsecops/cascavel-header-guard@v1
  with:
    urls: 'https://app.example.com,https://api.example.com'
    fail-score: '60'
```

### Strict mode (fail on missing critical headers)

```yaml
- uses: glferreira-devsecops/cascavel-header-guard@v1
  with:
    urls: 'https://production.example.com'
    fail-on-missing-critical: 'true'
    fail-score: '80'
```

## 🔍 Headers Checked

| Header | Category | Weight |
|:-------|:---------|:------:|
| `Strict-Transport-Security` | 🔴 Critical | 15 |
| `Content-Security-Policy` | 🔴 Critical | 15 |
| `X-Content-Type-Options` | 🔴 Critical | 10 |
| `X-Frame-Options` | 🟠 High | 8 |
| `Referrer-Policy` | 🟠 High | 7 |
| `Permissions-Policy` | 🟠 High | 7 |
| `Cross-Origin-Opener-Policy` | 🟠 High | 6 |
| `Cross-Origin-Resource-Policy` | 🟠 High | 6 |
| `Cross-Origin-Embedder-Policy` | 🟠 High | 5 |
| `X-XSS-Protection` | 🟠 High | 5 |
| `Cache-Control` | 🟡 Medium | 4 |
| `X-DNS-Prefetch-Control` | 🟡 Medium | 3 |
| `X-Download-Options` | 🟡 Medium | 3 |
| `X-Permitted-Cross-Domain-Policies` | 🟡 Medium | 3 |
| `Server` | ℹ️ Info | 2 |
| `X-Powered-By` | ℹ️ Info | 2 |

## ⚙️ Inputs

| Input | Description | Default |
|:------|:------------|:--------|
| `urls` | Comma-separated URLs to scan | _(required)_ |
| `fail-score` | Minimum passing score (0-100) | `50` |
| `fail-on-missing-critical` | Fail if HSTS/CSP/X-Content-Type missing | `true` |
| `timeout` | HTTP timeout in seconds | `10` |
| `follow-redirects` | Follow HTTP redirects | `true` |

## 📤 Outputs

| Output | Description |
|:-------|:------------|
| `total-score` | Average score across all URLs |
| `worst-score` | Lowest score |
| `missing-critical` | Missing critical headers count |
| `report-path` | Path to JSON report |

## 📄 License

MIT — [RET Tecnologia](https://rettecnologia.org)

---

<p align="center">
  <sub>🛡️ Built by <a href="https://github.com/glferreira-devsecops">@glferreira-devsecops</a> at <a href="https://rettecnologia.org">RET Tecnologia</a></sub>
</p>
