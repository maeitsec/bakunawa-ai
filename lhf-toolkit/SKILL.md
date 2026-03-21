---
name: lhf-toolkit
description: Low Hanging Fruit web security toolkit for authorized penetration testing. Covers the four most common quick-win checks — security headers analysis, DNS reconnaissance, HTTP methods & CORS testing, and information disclosure via HTTP responses. Use when user asks to "check headers", "scan DNS", "test CORS", "find info disclosure", "check SPF/DMARC", or "run a quick web security check". For authorized testing only.
metadata:
  author: maeitsec
  version: 1.0.0
---

# LHF Toolkit — Low Hanging Fruit Web Security Scanner

Four focused modules covering the most common, fastest-to-find web security weaknesses.

## Important

CRITICAL: Only test systems you have explicit written authorization to assess (signed SoW, bug bounty scope, or own infrastructure).

## Instructions

### Launch

```bash
python lhf_toolkit.py
```

Presents an interactive menu with 5 options (4 modules + full scan).

---

### Module 1: Security Headers Checker `[1]`

```
Select [1] > Security Headers Checker
Target > https://example.com
```

Checks for 9 critical HTTP security headers. Score is calculated as:

```
Score = (headers_present / 9) × 100
```

Grade scale:

| Grade | Score |
|-------|-------|
| A+    | 100   |
| A     | 90–99 |
| B     | 78–89 |
| C     | 56–77 |
| D     | 34–55 |
| F     | < 34  |

Headers checked with severity and CWE mapping:

| Header | Severity | CVSS | CWE |
|--------|----------|------|-----|
| Strict-Transport-Security | HIGH | 7.4 | CWE-319 |
| Content-Security-Policy | HIGH | 6.1 | CWE-79 |
| X-Content-Type-Options | MEDIUM | 5.3 | CWE-16 |
| X-Frame-Options | MEDIUM | 4.7 | CWE-1021 |
| Permissions-Policy | MEDIUM | 4.3 | CWE-16 |
| Cross-Origin-Opener-Policy | MEDIUM | 4.3 | CWE-346 |
| Cross-Origin-Resource-Policy | MEDIUM | 4.3 | CWE-346 |
| Cross-Origin-Embedder-Policy | MEDIUM | 4.3 | CWE-346 |
| Referrer-Policy | LOW | 3.1 | CWE-200 |

Output: grade, score out of 100, present/missing counts, max CVSS, and per-missing-header fix recommendations.

---

### Module 2: DNS Reconnaissance `[2]`

```
Select [2] > DNS Reconnaissance
Target > example.com
```

Collects per domain:
- **A record** — resolved IP
- **MX records** — mail server presence
- **NS records** — nameserver presence
- **SPF** — TXT record starting with `v=spf1`
- **DMARC** — `_dmarc.` TXT record with policy classification

DMARC policy grading:

| Policy | Risk |
|--------|------|
| `p=reject` | ✔ Strong — spoofing blocked |
| `p=quarantine` | ⚠ Weak — spoofing may succeed |
| `p=none` | ✗ Monitor only — no enforcement |
| Missing | ✗ Critical — fully spoofable |

Flags: missing SPF, missing DMARC, weak DMARC policy (`none` or `quarantine`).

---

### Module 3: HTTP Methods & CORS Checker `[3]`

```
Select [3] > HTTP Methods & CORS Checker
Target > https://example.com
```

Tests all 8 HTTP methods: `GET POST PUT DELETE PATCH OPTIONS HEAD TRACE`

Flags dangerous methods: `TRACE`, `PUT`, `DELETE`

CORS test — sends `Origin: https://evil.com` and evaluates:

| Condition | Severity |
|-----------|---------|
| `ACAO: *` | HIGH — wildcard exposes all data |
| `ACAO: https://evil.com` | HIGH — origin reflected back |
| Reflected + `ACAC: true` | CRITICAL — credential theft possible |

---

### Module 4: Information Disclosure Scanner `[4]`

```
Select [4] > Information Disclosure Scanner
Target > https://example.com
```

Detects technology and version information leaked via HTTP response headers and body.

**Header-based checks (13 headers):**

| Header | What It Leaks |
|--------|--------------|
| `Server` | Web server name + version |
| `X-Powered-By` | PHP, ASP.NET, Express version |
| `X-AspNet-Version` | .NET runtime version |
| `X-AspNetMvc-Version` | MVC framework version |
| `X-Generator` | CMS/framework (WordPress, Drupal) |
| `X-Drupal-Cache` | Drupal CMS usage |
| `Via` | Proxy software and version |
| `X-Runtime` | Rails/Ruby runtime info |
| `X-Backend-Server` | Internal hostname/IP |
| `X-Varnish` | Varnish cache + request IDs |
| `X-Cache` | Cache topology (HIT/MISS) |
| `X-CF-Powered-By` | ColdFusion usage |
| `X-Drupal-Dynamic-Cache` | Drupal CMS usage |

Version number detection: if a version string is found in a LOW/INFO header value, severity is automatically upgraded to MEDIUM.

**Body-based checks (14 patterns):**

| Pattern | Severity |
|---------|---------|
| PHP error/warning with file path | HIGH |
| Python/Django traceback | HIGH |
| Laravel/Symfony exception dump | HIGH |
| ASP.NET yellow screen of death | HIGH |
| Java/Spring stack trace | HIGH |
| Ruby on Rails exception page | HIGH |
| Node.js/Express error with path | HIGH |
| Django `DEBUG=True` active | HIGH |
| SQL error message leakage | HIGH |
| Sensitive HTML comments | MEDIUM |
| Internal RFC1918 IP in response | MEDIUM |
| WordPress version meta tag | LOW |
| Joomla meta generator tag | LOW |
| Drupal version string | LOW |

Output: per-target summary table + detailed per-finding breakdown with CWE, CVSS vector, body snippet, and remediation recommendation.

---

### Module 5: Full Scan `[5]`

Chains all 4 modules sequentially:

```
[1/4] Security Headers
[2/4] DNS Reconnaissance  (extracts domain from URL automatically)
[3/4] HTTP Methods & CORS
[4/4] Information Disclosure
```

---

## Input Modes

All modules support single target and batch file input:

```
[1] Single URL / domain / hostname
[2] File  — one target per line, # for comments
```

Example targets file:
```
# Production targets
https://app.example.com
https://api.example.com
# example.com   <- commented out
```

---

## Error Handling

| Issue | Cause | Fix |
|-------|-------|-----|
| `dnspython not installed` | Missing dep | `pip install dnspython` |
| `requests not installed` | Missing dep | `pip install requests` |
| SSL errors | Self-signed cert | Verify disabled by default |
| DNS resolution fails | Split-horizon DNS | Uses 8.8.8.8, 1.1.1.1, 9.9.9.9 fallback |

---

## Examples

### Example 1: Quick headers check
User says: "Check security headers on app.example.com"

Actions:
1. Launch `lhf_toolkit.py`
2. Select `[1]`
3. Enter `https://app.example.com`
4. Review grade, score, missing headers with fix recommendations

### Example 2: Batch DNS spoofing check
User says: "Check SPF and DMARC for these domains"

Actions:
1. Create `domains.txt` with one domain per line
2. Select `[2]` → File input
3. Flag `p=none`, `p=quarantine`, and missing DMARC as spoofing risks

### Example 3: Full quick-win sweep
User says: "Run all quick checks on https://target.com"

Actions:
1. Select `[5]` Full Scan
2. Enter target URL
3. All 4 modules run sequentially
4. Review per-module output
