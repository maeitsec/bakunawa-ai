#!/usr/bin/env python3
"""
Low Hanging Fruit - Web Security Toolkit
Author: @maeitsec
Purpose: Authorized penetration testing and security assessments
"""

import argparse
import os
import re
import socket
import ssl
import sys
from datetime import datetime
from urllib.parse import urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False
    print("[!] dnspython not installed. Run: pip install dnspython")

try:
    import idna
    HAS_IDNA = True
except ImportError:
    HAS_IDNA = False

__version__ = "1.0.0"

DNS_TIME = 3
RESOLVERS = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]

class Colors:
    PURPLE   = '\033[95m'
    OKBLUE   = '\033[94m'
    OKCYAN   = '\033[96m'
    OKGREEN  = '\033[92m'
    WARNING  = '\033[93m'
    FAIL     = '\033[91m'
    ENDC     = '\033[0m'
    BOLD     = '\033[1m'
    GRAY     = '\033[90m'

def print_main_banner():
    print(f"""
{Colors.PURPLE}╔══════════════════════════════════════════════════════════════════╗
║   _     _   _____   ______    _______   _____   _      _  __   ║
║  | |   | | |  ___| |  ____|  |__   __| |  __ \ | |    | ||  |  ║
║  | |   | | | |__   | |__        | |    | |  | || |    | ||  |  ║
║  | |   | | |  __|  |  __|       | |    | |  | || |    | ||  |  ║
║  | |___| | | |___  | |          | |    | |__| || |____| ||__|  ║
║  |_______| |_____| |_|          |_|    |_____/ |________||__|  ║
║                                                                  ║
║         LOW HANGING FRUIT — WEB SECURITY TOOLKIT v{__version__}      ║
║                    Authorized Testing Only                       ║
╚══════════════════════════════════════════════════════════════════╝{Colors.ENDC}
""")

def print_tool_menu():
    print(f"""
{Colors.PURPLE}┌─────────────────────────────────────────────┐
│          AVAILABLE SECURITY TOOLS           │
├─────────────────────────────────────────────┤{Colors.ENDC}
│  {Colors.BOLD}[1]{Colors.ENDC} Security Headers Checker               │
│  {Colors.BOLD}[2]{Colors.ENDC} DNS Reconnaissance                     │
│  {Colors.BOLD}[3]{Colors.ENDC} HTTP Methods & CORS Checker            │
│  {Colors.BOLD}[4]{Colors.ENDC} Information Disclosure Scanner         │
│  {Colors.BOLD}[5]{Colors.ENDC} Full Scan (All Modules)                │
│  {Colors.BOLD}[0]{Colors.ENDC} Exit                                   │
{Colors.PURPLE}└─────────────────────────────────────────────┘{Colors.ENDC}
""")

# ============================================================================
# SECURITY HEADERS CHECKER
# ============================================================================

class SecurityHeadersChecker:
    # 9 headers, each worth 11 pts = 99 max. We treat presence of all 9 = 100.
    # Score = (present_count / total_count) * 100, rounded.
    SECURITY_HEADERS = {
        'Strict-Transport-Security': {
            'severity': 'HIGH', 'cvss': 7.4,
            'cvss_vector': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N',
            'cwe': 'CWE-319',
            'description': 'Prevents downgrade attacks and cookie hijacking',
            'recommendation': 'Strict-Transport-Security: max-age=31536000; includeSubDomains'
        },
        'Content-Security-Policy': {
            'severity': 'HIGH', 'cvss': 6.1,
            'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
            'cwe': 'CWE-79',
            'description': 'Prevents XSS and data injection attacks',
            'recommendation': "Content-Security-Policy: default-src 'self'"
        },
        'X-Frame-Options': {
            'severity': 'MEDIUM', 'cvss': 4.7,
            'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N',
            'cwe': 'CWE-1021',
            'description': 'Prevents clickjacking attacks',
            'recommendation': 'X-Frame-Options: DENY or SAMEORIGIN'
        },
        'X-Content-Type-Options': {
            'severity': 'MEDIUM', 'cvss': 5.3,
            'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N',
            'cwe': 'CWE-16',
            'description': 'Prevents MIME-type sniffing',
            'recommendation': 'X-Content-Type-Options: nosniff'
        },
        'Referrer-Policy': {
            'severity': 'LOW', 'cvss': 3.1,
            'cvss_vector': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N',
            'cwe': 'CWE-200',
            'description': 'Controls referrer information leakage',
            'recommendation': 'Referrer-Policy: strict-origin-when-cross-origin'
        },
        'Permissions-Policy': {
            'severity': 'MEDIUM', 'cvss': 4.3,
            'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N',
            'cwe': 'CWE-16',
            'description': 'Controls browser features and APIs',
            'recommendation': 'Permissions-Policy: geolocation=(), camera=(), microphone=()'
        },
        'Cross-Origin-Opener-Policy': {
            'severity': 'MEDIUM', 'cvss': 4.3,
            'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N',
            'cwe': 'CWE-346',
            'description': 'Prevents cross-origin attacks (Spectre)',
            'recommendation': 'Cross-Origin-Opener-Policy: same-origin'
        },
        'Cross-Origin-Resource-Policy': {
            'severity': 'MEDIUM', 'cvss': 4.3,
            'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N',
            'cwe': 'CWE-346',
            'description': 'Controls cross-origin resource loading',
            'recommendation': 'Cross-Origin-Resource-Policy: same-origin'
        },
        'Cross-Origin-Embedder-Policy': {
            'severity': 'MEDIUM', 'cvss': 4.3,
            'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N',
            'cwe': 'CWE-346',
            'description': 'Controls cross-origin embedding',
            'recommendation': 'Cross-Origin-Embedder-Policy: require-corp'
        },
    }

    TOTAL = len(SECURITY_HEADERS)  # 9

    def __init__(self, timeout=10):
        self.timeout = timeout

    def check_url(self, url, verify_ssl=False):
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        result = {
            'url': url, 'status': None,
            'present': [], 'missing': [],
            'score': 0, 'grade': 'F', 'max_cvss': 0.0
        }
        try:
            response = requests.get(url, timeout=self.timeout, verify=verify_ssl, allow_redirects=True)
            result['status'] = response.status_code
            headers_lower = {k.lower(): v for k, v in response.headers.items()}

            present_count = 0
            for header, info in self.SECURITY_HEADERS.items():
                if header.lower() in headers_lower:
                    result['present'].append({'header': header, 'value': headers_lower[header.lower()]})
                    present_count += 1
                else:
                    result['missing'].append({**info, 'header': header})
                    if info['cvss'] > result['max_cvss']:
                        result['max_cvss'] = info['cvss']

            # Score: percentage of headers present, 0-100
            result['score'] = round((present_count / self.TOTAL) * 100)
            s = result['score']
            result['grade'] = 'A+' if s == 100 else 'A' if s >= 90 else 'B' if s >= 78 else 'C' if s >= 56 else 'D' if s >= 34 else 'F'

        except Exception as e:
            result['status'] = 'ERROR'
            result['error'] = str(e)[:50]
        return result

    @staticmethod
    def _abbr(header):
        return (header
            .replace('Strict-Transport-Security', 'HSTS')
            .replace('Content-Security-Policy', 'CSP')
            .replace('X-Content-Type-Options', 'XCTO')
            .replace('X-Frame-Options', 'XFO')
            .replace('Referrer-Policy', 'RP')
            .replace('Permissions-Policy', 'PP')
            .replace('Cross-Origin-Opener-Policy', 'COOP')
            .replace('Cross-Origin-Resource-Policy', 'CORP')
            .replace('Cross-Origin-Embedder-Policy', 'COEP'))

    def print_batch_summary(self, results):
        W = 115
        print(f"\n{Colors.PURPLE}{'═'*W}{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.PURPLE}SECURITY HEADERS SCAN RESULTS{Colors.ENDC}")
        print(f"{Colors.PURPLE}{'═'*W}{Colors.ENDC}")
        print(f"{Colors.GRAY}Scanned: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Targets: {len(results)} | Max score: 100 (9/9 headers present){Colors.ENDC}\n")

        print(f"{'─'*W}")
        print(f"{Colors.BOLD}{'TARGET':<50} {'STATUS':<7} {'GRADE':<6} {'SCORE':<8} {'PRESENT':<9} {'MISSING':<9} {'MAX CVSS'}{Colors.ENDC}")
        print(f"{'─'*W}")

        for r in results:
            url = r['url'][:48] + '..' if len(r['url']) > 50 else r['url']
            if r['status'] == 'ERROR':
                print(f"{url:<50} {Colors.FAIL}{'ERR':<7}{Colors.ENDC} {'-':<6} {'-':<8} {'-':<9} {'-':<9} {r.get('error','')[:20]}")
                continue

            gc = Colors.OKGREEN if r['grade'] in ('A+','A','B') else Colors.WARNING if r['grade'] in ('C','D') else Colors.FAIL
            sc = Colors.OKGREEN if r['status'] == 200 else Colors.WARNING
            cc = Colors.FAIL if r['max_cvss'] >= 7 else Colors.WARNING if r['max_cvss'] >= 4 else Colors.OKBLUE

            print(f"{url:<50} {sc}{r['status']:<7}{Colors.ENDC} "
                  f"{gc}{r['grade']:<6}{Colors.ENDC} "
                  f"{gc}{r['score']:>3}/100{Colors.ENDC}  "
                  f"{Colors.OKGREEN}{len(r['present']):<9}{Colors.ENDC}"
                  f"{Colors.FAIL if r['missing'] else Colors.GRAY}{len(r['missing']):<9}{Colors.ENDC}"
                  f"{cc}{r['max_cvss']:.1f}{Colors.ENDC}")

        print(f"{'─'*W}")

        print(f"\n{Colors.BOLD}DETAILED FINDINGS:{Colors.ENDC}\n")
        for r in results:
            if r['status'] == 'ERROR':
                print(f"{Colors.FAIL}✗ {r['url']}{Colors.ENDC} — {r.get('error','')}\n")
                continue
            gc = Colors.OKGREEN if r['grade'] in ('A+','A','B') else Colors.WARNING if r['grade'] in ('C','D') else Colors.FAIL
            print(f"{gc}[{r['grade']}]{Colors.ENDC} {r['url']}  "
                  f"{Colors.GRAY}score:{Colors.ENDC} {gc}{r['score']}/100{Colors.ENDC}  "
                  f"{Colors.GRAY}cvss:{Colors.ENDC} {r['max_cvss']}")

            if r['present']:
                abbrs = [self._abbr(h['header']) for h in r['present']]
                print(f"  {Colors.OKGREEN}✔ Present  ({len(r['present'])}/{self.TOTAL}):{Colors.ENDC} {', '.join(abbrs)}")
            if r['missing']:
                items = [f"{self._abbr(h['header'])}({h['cvss']})" for h in r['missing']]
                print(f"  {Colors.FAIL}✗ Missing  ({len(r['missing'])}/{self.TOTAL}):{Colors.ENDC} {', '.join(items)}")
                print(f"\n  {Colors.BOLD}Recommendations:{Colors.ENDC}")
                for h in r['missing']:
                    sc2 = Colors.FAIL if h['severity']=='HIGH' else Colors.WARNING if h['severity']=='MEDIUM' else Colors.OKBLUE
                    print(f"    {sc2}[{h['severity']}]{Colors.ENDC} {h['header']}")
                    print(f"      Add: {Colors.OKCYAN}{h['recommendation']}{Colors.ENDC}")
            print()

        print(f"{Colors.GRAY}Grade scale: A+(100) A(90-99) B(78-89) C(56-77) D(34-55) F(<34){Colors.ENDC}")
        print(f"{Colors.GRAY}Abbrev: HSTS · CSP · XFO · XCTO · RP · PP · COOP · CORP · COEP{Colors.ENDC}")
        print(f"{Colors.PURPLE}{'═'*W}{Colors.ENDC}\n")

# ============================================================================
# DNS RECONNAISSANCE
# ============================================================================

class DNSRecon:
    def __init__(self):
        self.timeout = DNS_TIME

    def query(self, rdtype, domain):
        if not HAS_DNS:
            return []
        for r in RESOLVERS:
            try:
                resolver = dns.resolver.Resolver(configure=False)
                resolver.nameservers = [r]
                resolver.timeout = self.timeout
                return [str(rr) for rr in resolver.resolve(domain, rdtype)]
            except:
                pass
        return []

    def check_domain(self, domain):
        if HAS_IDNA:
            try:
                domain = idna.encode(domain.rstrip('.')).decode('ascii')
            except:
                pass

        result = {
            'domain': domain, 'ns': [], 'mx': [], 'a': [],
            'spf': None, 'dmarc': None, 'dmarc_policy': None
        }
        result['ns'] = self.query('NS', domain)
        result['mx'] = self.query('MX', domain)
        result['a']  = self.query('A',  domain)

        for t in self.query('TXT', domain):
            if 'v=spf1' in t.lower():
                result['spf'] = t
                break

        for d in self.query('TXT', f'_dmarc.{domain}'):
            if 'v=dmarc1' in d.lower():
                result['dmarc'] = d
                result['dmarc_policy'] = (
                    'reject'     if 'p=reject'     in d.lower() else
                    'quarantine' if 'p=quarantine' in d.lower() else
                    'none'
                )
                break

        return result

    def print_batch_summary(self, results):
        W = 115
        print(f"\n{Colors.PURPLE}{'═'*W}{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.PURPLE}DNS RECONNAISSANCE RESULTS{Colors.ENDC}")
        print(f"{Colors.PURPLE}{'═'*W}{Colors.ENDC}")
        print(f"{Colors.GRAY}Scanned: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Targets: {len(results)}{Colors.ENDC}\n")

        print(f"{'─'*W}")
        print(f"{Colors.BOLD}{'DOMAIN':<35} {'A RECORD':<18} {'MX':<5} {'NS':<5} {'SPF':<8} {'DMARC':<14} {'ISSUES'}{Colors.ENDC}")
        print(f"{'─'*W}")

        for r in results:
            domain = r['domain'][:33] + '..' if len(r['domain']) > 35 else r['domain']
            a_rec  = r['a'][0] if r['a'] else '-'
            mx     = Colors.OKGREEN + '✔' + Colors.ENDC if r['mx'] else Colors.GRAY + '-' + Colors.ENDC
            ns     = Colors.OKGREEN + '✔' + Colors.ENDC if r['ns'] else Colors.GRAY + '-' + Colors.ENDC
            spf    = Colors.OKGREEN + '✔' + Colors.ENDC if r['spf'] else Colors.FAIL + '✗' + Colors.ENDC

            if r['dmarc']:
                dmarc = {
                    'reject':     Colors.OKGREEN  + 'p=reject'     + Colors.ENDC,
                    'quarantine': Colors.WARNING   + 'p=quarantine' + Colors.ENDC,
                    'none':       Colors.FAIL      + 'p=none'       + Colors.ENDC,
                }.get(r['dmarc_policy'], Colors.GRAY + r['dmarc_policy'] + Colors.ENDC)
            else:
                dmarc = Colors.FAIL + '✗ Missing' + Colors.ENDC

            issues = []
            if not r['spf']:                         issues.append('No SPF')
            if not r['dmarc']:                       issues.append('No DMARC')
            elif r['dmarc_policy'] == 'none':        issues.append('DMARC p=none')
            elif r['dmarc_policy'] == 'quarantine':  issues.append('Weak DMARC')
            issue_str = ', '.join(issues) if issues else Colors.OKGREEN + 'OK' + Colors.ENDC

            print(f"{domain:<35} {a_rec:<18} {mx:<14} {ns:<14} {spf:<17} {dmarc:<23} {issue_str}")

        print(f"{'─'*W}")

        no_spf      = sum(1 for r in results if not r['spf'])
        no_dmarc    = sum(1 for r in results if not r['dmarc'])
        weak_dmarc  = sum(1 for r in results if r['dmarc_policy'] in ('none', 'quarantine'))

        print(f"\n{Colors.BOLD}SUMMARY:{Colors.ENDC}")
        print(f"  {Colors.GRAY}├─{Colors.ENDC} Total domains       : {len(results)}")
        if no_spf:
            print(f"  {Colors.GRAY}├─{Colors.ENDC} {Colors.FAIL}Missing SPF         : {no_spf}{Colors.ENDC}")
        if no_dmarc:
            print(f"  {Colors.GRAY}├─{Colors.ENDC} {Colors.FAIL}Missing DMARC       : {no_dmarc}{Colors.ENDC}")
        if weak_dmarc:
            print(f"  {Colors.GRAY}└─{Colors.ENDC} {Colors.WARNING}Weak DMARC policy   : {weak_dmarc}{Colors.ENDC}")
        print(f"{Colors.PURPLE}{'═'*W}{Colors.ENDC}\n")

# ============================================================================
# HTTP METHODS & CORS CHECKER
# ============================================================================

class HTTPMethodsChecker:
    METHODS   = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD', 'TRACE']
    DANGEROUS = ['TRACE', 'PUT', 'DELETE']

    def __init__(self, timeout=5):
        self.timeout = timeout

    def check_url(self, url):
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        result = {
            'url': url, 'allowed': [], 'dangerous': [],
            'cors_acao': None, 'cors_acac': None, 'status': 'OK'
        }
        try:
            for method in self.METHODS:
                try:
                    resp = requests.request(method, url, timeout=self.timeout, verify=False, allow_redirects=False)
                    if resp.status_code not in [405, 501]:
                        result['allowed'].append(method)
                        if method in self.DANGEROUS:
                            result['dangerous'].append(method)
                except:
                    pass

            try:
                resp = requests.options(url, headers={'Origin': 'https://evil.com'},
                                        timeout=self.timeout, verify=False)
                result['cors_acao'] = resp.headers.get('Access-Control-Allow-Origin', '')
                result['cors_acac'] = resp.headers.get('Access-Control-Allow-Credentials', '')
            except:
                pass
        except Exception as e:
            result['status'] = 'ERROR'
            result['error'] = str(e)[:40]

        return result

    def print_batch_summary(self, results):
        W = 115
        print(f"\n{Colors.PURPLE}{'═'*W}{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.PURPLE}HTTP METHODS & CORS SCAN RESULTS{Colors.ENDC}")
        print(f"{Colors.PURPLE}{'═'*W}{Colors.ENDC}")
        print(f"{Colors.GRAY}Scanned: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Targets: {len(results)}{Colors.ENDC}\n")

        print(f"{'─'*W}")
        print(f"{Colors.BOLD}{'TARGET':<45} {'ALLOWED METHODS':<35} {'DANGEROUS':<15} {'CORS ACAO':<15} {'ISSUES'}{Colors.ENDC}")
        print(f"{'─'*W}")

        for r in results:
            url = r['url'][:43] + '..' if len(r['url']) > 45 else r['url']
            if r['status'] == 'ERROR':
                print(f"{url:<45} {Colors.FAIL}{'-':<35}{Colors.ENDC} {'-':<15} {'-':<15} ERROR")
                continue

            allowed   = ','.join(r['allowed'])
            allowed   = allowed[:33] + '..' if len(allowed) > 35 else allowed
            dangerous = ','.join(r['dangerous']) if r['dangerous'] else '-'
            dc        = Colors.FAIL if r['dangerous'] else Colors.GRAY

            acao = r['cors_acao'] or '-'
            if acao == '*':
                ac, acao_disp = Colors.FAIL, '*'
            elif acao == 'https://evil.com':
                ac, acao_disp = Colors.FAIL, 'REFLECTS!'
            else:
                ac, acao_disp = Colors.GRAY, acao[:13] + '..' if len(acao) > 15 else acao

            issues = []
            if r['dangerous']:
                issues.append(f"Dangerous:{','.join(r['dangerous'])}")
            if r['cors_acao'] == '*':
                issues.append('CORS wildcard')
            if r['cors_acao'] == 'https://evil.com':
                issues.append('CORS reflects origin')
            if r['cors_acao'] == 'https://evil.com' and r['cors_acac'] == 'true':
                issues.append('CORS+Credentials=CRITICAL')

            issue_str = '; '.join(issues) if issues else Colors.OKGREEN + 'OK' + Colors.ENDC

            print(f"{url:<45} {allowed:<35} {dc}{dangerous:<15}{Colors.ENDC} {ac}{acao_disp:<15}{Colors.ENDC} {issue_str}")

        print(f"{'─'*W}")

        dangerous_hosts = [r['url'] for r in results if r.get('dangerous')]
        cors_issues     = [r['url'] for r in results if r.get('cors_acao') in ('*', 'https://evil.com')]

        if dangerous_hosts or cors_issues:
            print(f"\n{Colors.BOLD}FINDINGS:{Colors.ENDC}")
            for url in dangerous_hosts:
                r = next(x for x in results if x['url'] == url)
                print(f"  {Colors.FAIL}✗{Colors.ENDC} Dangerous methods enabled on {url}: {','.join(r['dangerous'])}")
            for url in cors_issues:
                r = next(x for x in results if x['url'] == url)
                cred = f" + Credentials=true" if r.get('cors_acac') == 'true' else ''
                print(f"  {Colors.FAIL}✗{Colors.ENDC} CORS misconfiguration on {url}: ACAO={r['cors_acao']}{cred}")

        print(f"{Colors.PURPLE}{'═'*W}{Colors.ENDC}\n")

# ============================================================================
# INFORMATION DISCLOSURE SCANNER
# ============================================================================

class InfoDisclosureScanner:
    """
    Detects technology/version information leaked via HTTP response headers and body.
    CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
    """

    DISCLOSURE_HEADERS = {
        'Server': {
            'severity': 'MEDIUM', 'cvss': 5.3,
            'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
            'cwe': 'CWE-200',
            'description': 'Discloses web server software and version',
            'recommendation': 'Remove or genericize: Server: webserver',
            'version_regex': r'[\d]+\.[\d]+[\.\d]*'
        },
        'X-Powered-By': {
            'severity': 'MEDIUM', 'cvss': 5.3,
            'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
            'cwe': 'CWE-200',
            'description': 'Discloses backend technology (PHP, ASP.NET, Express, etc.)',
            'recommendation': 'Remove header entirely or suppress via framework config',
            'version_regex': r'[\d]+\.[\d]+[\.\d]*'
        },
        'X-AspNet-Version': {
            'severity': 'MEDIUM', 'cvss': 5.3,
            'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
            'cwe': 'CWE-200',
            'description': 'Discloses ASP.NET runtime version',
            'recommendation': 'Set <httpRuntime enableVersionHeader="false" /> in web.config',
            'version_regex': r'[\d]+\.[\d]+[\.\d]*'
        },
        'X-AspNetMvc-Version': {
            'severity': 'MEDIUM', 'cvss': 5.3,
            'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
            'cwe': 'CWE-200',
            'description': 'Discloses ASP.NET MVC version',
            'recommendation': 'MvcHandler.DisableMvcResponseHeader = true in Global.asax',
            'version_regex': r'[\d]+\.[\d]+[\.\d]*'
        },
        'X-Generator': {
            'severity': 'LOW', 'cvss': 3.7,
            'cvss_vector': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N',
            'cwe': 'CWE-200',
            'description': 'Discloses CMS or framework (WordPress, Drupal, etc.)',
            'recommendation': 'Remove or suppress the X-Generator header in CMS config',
            'version_regex': r'[\d]+\.[\d]+[\.\d]*'
        },
        'X-Drupal-Cache': {
            'severity': 'LOW', 'cvss': 3.1,
            'cvss_vector': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N',
            'cwe': 'CWE-200',
            'description': 'Discloses Drupal CMS usage',
            'recommendation': 'Suppress via Drupal performance/cache config',
            'version_regex': None
        },
        'X-Drupal-Dynamic-Cache': {
            'severity': 'LOW', 'cvss': 3.1,
            'cvss_vector': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N',
            'cwe': 'CWE-200',
            'description': 'Discloses Drupal CMS usage',
            'recommendation': 'Suppress via Drupal performance/cache config',
            'version_regex': None
        },
        'Via': {
            'severity': 'LOW', 'cvss': 3.1,
            'cvss_vector': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N',
            'cwe': 'CWE-200',
            'description': 'Discloses proxy/gateway software and version',
            'recommendation': 'Configure proxy to suppress or genericize the Via header',
            'version_regex': r'[\d]+\.[\d]+[\.\d]*'
        },
        'X-Runtime': {
            'severity': 'LOW', 'cvss': 3.1,
            'cvss_vector': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N',
            'cwe': 'CWE-200',
            'description': 'Discloses application runtime info (Rails/Ruby)',
            'recommendation': 'Disable in production Rails config',
            'version_regex': None
        },
        'X-Backend-Server': {
            'severity': 'MEDIUM', 'cvss': 5.3,
            'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
            'cwe': 'CWE-200',
            'description': 'Discloses internal backend server hostname/IP',
            'recommendation': 'Remove header from load balancer / reverse proxy config',
            'version_regex': None
        },
        'X-Varnish': {
            'severity': 'LOW', 'cvss': 3.1,
            'cvss_vector': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N',
            'cwe': 'CWE-200',
            'description': 'Discloses Varnish cache usage and request IDs',
            'recommendation': 'unset beresp.http.X-Varnish in VCL',
            'version_regex': None
        },
        'X-Cache': {
            'severity': 'INFO', 'cvss': 0.0,
            'cvss_vector': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N',
            'cwe': 'CWE-200',
            'description': 'Reveals caching infrastructure (HIT/MISS leaks topology)',
            'recommendation': 'Remove or suppress X-Cache from CDN/proxy config',
            'version_regex': None
        },
        'X-CF-Powered-By': {
            'severity': 'LOW', 'cvss': 3.1,
            'cvss_vector': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N',
            'cwe': 'CWE-200',
            'description': 'Discloses ColdFusion usage',
            'recommendation': 'Disable in ColdFusion Administrator > Server Settings',
            'version_regex': r'[\d]+\.[\d]+[\.\d]*'
        },
    }

    BODY_PATTERNS = [
        {
            'name': 'PHP error/warning',
            'pattern': r'(Warning:|Fatal error:|Parse error:|Notice:)\s+.+\s+in\s+/.+\.php\s+on line\s+\d+',
            'severity': 'HIGH', 'cvss': 7.5, 'cwe': 'CWE-209',
            'description': 'PHP stack trace reveals file paths and source code structure',
            'recommendation': 'Set display_errors=Off and log_errors=On in php.ini'
        },
        {
            'name': 'Python/Django traceback',
            'pattern': r'Traceback \(most recent call last\):|Django Version:',
            'severity': 'HIGH', 'cvss': 7.5, 'cwe': 'CWE-209',
            'description': 'Django debug page exposes stack trace and configuration',
            'recommendation': 'Set DEBUG=False in settings.py for production'
        },
        {
            'name': 'Laravel/Symfony exception',
            'pattern': r'(Illuminate\\|Symfony\\Component\\|Whoops!|Stack trace:).+Exception',
            'severity': 'HIGH', 'cvss': 7.5, 'cwe': 'CWE-209',
            'description': 'Laravel/Symfony exception handler exposes stack trace',
            'recommendation': 'Set APP_DEBUG=false and APP_ENV=production in .env'
        },
        {
            'name': 'ASP.NET error page',
            'pattern': r'(Server Error in|ASP\.NET is configured|Runtime Error|Compilation Error).+Application',
            'severity': 'HIGH', 'cvss': 7.5, 'cwe': 'CWE-209',
            'description': 'ASP.NET yellow screen of death exposes stack trace',
            'recommendation': 'Set <customErrors mode="On"> in web.config'
        },
        {
            'name': 'Java/Spring stack trace',
            'pattern': r'(java\..+Exception|org\.springframework\.|at [a-z]+\.[a-zA-Z]+\.[a-zA-Z]+\()',
            'severity': 'HIGH', 'cvss': 7.5, 'cwe': 'CWE-209',
            'description': 'Java stack trace reveals internal class structure',
            'recommendation': 'Configure custom error pages; disable stack traces in production'
        },
        {
            'name': 'Ruby on Rails error',
            'pattern': r'(ActionController::|ActiveRecord::|RuntimeError|app/controllers|app/models).+\.rb:\d+',
            'severity': 'HIGH', 'cvss': 7.5, 'cwe': 'CWE-209',
            'description': 'Rails exception page exposes source code and paths',
            'recommendation': 'Set config.consider_all_requests_local = false in production.rb'
        },
        {
            'name': 'Node.js/Express error',
            'pattern': r'(Error:|ReferenceError:|TypeError:)\s+.+\n\s+at\s+.+\(/.+\.js:\d+:\d+\)',
            'severity': 'HIGH', 'cvss': 7.5, 'cwe': 'CWE-209',
            'description': 'Node.js stack trace reveals file paths',
            'recommendation': 'Use express error handler; never send stack traces to client'
        },
        {
            'name': 'Django DEBUG=True active',
            'pattern': r'You\'re seeing this error because you have DEBUG\s*=\s*True',
            'severity': 'HIGH', 'cvss': 7.5, 'cwe': 'CWE-94',
            'description': 'Django is running in debug mode — full config exposed',
            'recommendation': 'Set DEBUG=False in settings.py immediately'
        },
        {
            'name': 'WordPress version disclosure',
            'pattern': r'<meta name="generator" content="WordPress [\d.]+',
            'severity': 'LOW', 'cvss': 3.7, 'cwe': 'CWE-200',
            'description': 'WordPress version exposed in HTML meta generator tag',
            'recommendation': 'remove_action("wp_head", "wp_generator") in functions.php'
        },
        {
            'name': 'Joomla version disclosure',
            'pattern': r'<meta name="generator" content="Joomla',
            'severity': 'LOW', 'cvss': 3.7, 'cwe': 'CWE-200',
            'description': 'Joomla CMS disclosed via meta generator tag',
            'recommendation': 'Disable meta generator in Joomla Global Configuration'
        },
        {
            'name': 'Drupal version disclosure',
            'pattern': r'Drupal [\d.]+ \(',
            'severity': 'LOW', 'cvss': 3.7, 'cwe': 'CWE-200',
            'description': 'Drupal version exposed in HTML',
            'recommendation': 'Enable Drupal security hardening; disable version display'
        },
        {
            'name': 'Sensitive HTML comment',
            'pattern': r'<!--.*(password|secret|key|token|api_key|todo|hack|fixme|debug|admin|internal|staging).+-->',
            'severity': 'MEDIUM', 'cvss': 5.3, 'cwe': 'CWE-615',
            'description': 'HTML comment contains potentially sensitive keywords',
            'recommendation': 'Audit and remove all sensitive HTML comments before deployment'
        },
        {
            'name': 'SQL error disclosure',
            'pattern': r'(SQL syntax|mysql_fetch|ORA-\d+|Microsoft OLE DB|ODBC SQL Server|pg_query\(\)|SQLite)',
            'severity': 'HIGH', 'cvss': 7.5, 'cwe': 'CWE-209',
            'description': 'Database error message leaked in HTTP response body',
            'recommendation': 'Suppress DB errors; use parameterized queries; enable server-side logging only'
        },
        {
            'name': 'Internal IP in response',
            'pattern': r'(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)',
            'severity': 'MEDIUM', 'cvss': 5.3, 'cwe': 'CWE-200',
            'description': 'Internal RFC1918 IP address leaked in HTTP response',
            'recommendation': 'Audit response bodies and headers for internal network references'
        },
    ]

    def __init__(self, timeout=10):
        self.timeout = timeout

    def scan_url(self, url):
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        result = {
            'url': url, 'status': 'OK',
            'header_findings': [], 'body_findings': [],
            'total': 0, 'max_cvss': 0.0,
        }
        try:
            resp = requests.get(
                url, timeout=self.timeout, verify=False, allow_redirects=True,
                headers={'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)'}
            )
            headers_lower = {k.lower(): v for k, v in resp.headers.items()}
            body = resp.text[:50000]

            for header, info in self.DISCLOSURE_HEADERS.items():
                val = headers_lower.get(header.lower())
                if not val:
                    continue
                has_version = bool(info['version_regex'] and re.search(info['version_regex'], val))
                finding = {
                    'header': header, 'value': val[:80],
                    'has_version': has_version,
                    **{k: info[k] for k in ('severity','cvss','cvss_vector','cwe','description','recommendation')}
                }
                if has_version and finding['severity'] in ('LOW', 'INFO'):
                    finding['severity'] = 'MEDIUM'
                    finding['cvss'] = max(finding['cvss'], 5.3)
                result['header_findings'].append(finding)
                if finding['cvss'] > result['max_cvss']:
                    result['max_cvss'] = finding['cvss']

            for pi in self.BODY_PATTERNS:
                m = re.search(pi['pattern'], body, re.IGNORECASE | re.DOTALL)
                if not m:
                    continue
                snippet = m.group(0)[:120].replace('\n',' ').replace('\r','')
                finding = {
                    'name': pi['name'], 'snippet': snippet,
                    **{k: pi[k] for k in ('severity','cvss','cwe','description','recommendation')}
                }
                result['body_findings'].append(finding)
                if finding['cvss'] > result['max_cvss']:
                    result['max_cvss'] = finding['cvss']

            result['total'] = len(result['header_findings']) + len(result['body_findings'])

        except Exception as e:
            result['status'] = 'ERROR'
            result['error'] = str(e)[:50]

        return result

    def _sev_color(self, sev):
        return {'HIGH': Colors.FAIL, 'MEDIUM': Colors.WARNING,
                'LOW': Colors.OKBLUE, 'INFO': Colors.GRAY}.get(sev, Colors.GRAY)

    def print_batch_summary(self, results):
        W = 115
        print(f"\n{Colors.PURPLE}{'═'*W}{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.PURPLE}INFORMATION DISCLOSURE SCAN RESULTS{Colors.ENDC}")
        print(f"{Colors.PURPLE}{'═'*W}{Colors.ENDC}")
        print(f"{Colors.GRAY}Scanned: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Targets: {len(results)}{Colors.ENDC}\n")

        print(f"{'─'*W}")
        print(f"{Colors.BOLD}{'TARGET':<50} {'STATUS':<8} {'HDR':<6} {'BODY':<6} {'MAX CVSS':<10} {'VERDICT'}{Colors.ENDC}")
        print(f"{'─'*W}")

        for r in results:
            url = r['url'][:48] + '..' if len(r['url']) > 50 else r['url']
            if r['status'] == 'ERROR':
                print(f"{url:<50} {Colors.FAIL}{'ERROR':<8}{Colors.ENDC} {'-':<6} {'-':<6} {'-':<10} {r.get('error','')[:20]}")
                continue
            mc = r['max_cvss']
            vc = Colors.FAIL if mc >= 7 else Colors.WARNING if mc >= 4 else Colors.OKBLUE if mc > 0 else Colors.OKGREEN
            verdict = ('CRITICAL' if mc >= 9 else 'HIGH' if mc >= 7 else
                       'MEDIUM'   if mc >= 4 else 'LOW'  if mc > 0 else 'CLEAN')
            hf = len(r['header_findings'])
            bf = len(r['body_findings'])
            print(f"{url:<50} {Colors.OKGREEN}{'200':<8}{Colors.ENDC} "
                  f"{Colors.FAIL if hf else Colors.GRAY}{hf:<6}{Colors.ENDC}"
                  f"{Colors.FAIL if bf else Colors.GRAY}{bf:<6}{Colors.ENDC}"
                  f"{vc}{mc:<10.1f}{Colors.ENDC}{vc}{verdict}{Colors.ENDC}")

        print(f"{'─'*W}")

        for r in results:
            if r['status'] == 'ERROR' or r['total'] == 0:
                continue
            print(f"\n{Colors.BOLD}{'─'*W}{Colors.ENDC}")
            print(f"{Colors.BOLD}{r['url']}{Colors.ENDC}  {Colors.GRAY}max CVSS: {r['max_cvss']}{Colors.ENDC}")

            if r['header_findings']:
                print(f"\n  {Colors.BOLD}Header Disclosure:{Colors.ENDC}")
                for f in r['header_findings']:
                    sc = self._sev_color(f['severity'])
                    vtag = f" {Colors.FAIL}[VERSION EXPOSED]{Colors.ENDC}" if f['has_version'] else ''
                    print(f"  {sc}[{f['severity']}]{Colors.ENDC} {Colors.BOLD}{f['header']}{Colors.ENDC}{vtag}")
                    print(f"    {Colors.GRAY}Value  :{Colors.ENDC} {f['value']}")
                    print(f"    {Colors.GRAY}CWE    :{Colors.ENDC} {f['cwe']}  CVSS: {f['cvss']}  {f['cvss_vector']}")
                    print(f"    {Colors.GRAY}Detail :{Colors.ENDC} {f['description']}")
                    print(f"    {Colors.OKCYAN}Fix    :{Colors.ENDC} {f['recommendation']}\n")

            if r['body_findings']:
                print(f"  {Colors.BOLD}Body Disclosure:{Colors.ENDC}")
                for f in r['body_findings']:
                    sc = self._sev_color(f['severity'])
                    print(f"  {sc}[{f['severity']}]{Colors.ENDC} {Colors.BOLD}{f['name']}{Colors.ENDC}")
                    print(f"    {Colors.GRAY}CWE    :{Colors.ENDC} {f['cwe']}  CVSS: {f['cvss']}")
                    print(f"    {Colors.GRAY}Detail :{Colors.ENDC} {f['description']}")
                    print(f"    {Colors.GRAY}Snippet:{Colors.ENDC} {Colors.FAIL}{f['snippet'][:100]}{Colors.ENDC}")
                    print(f"    {Colors.OKCYAN}Fix    :{Colors.ENDC} {f['recommendation']}\n")

        total_hdr  = sum(len(r['header_findings']) for r in results if r['status'] != 'ERROR')
        total_body = sum(len(r['body_findings'])   for r in results if r['status'] != 'ERROR')
        high_count = sum(1 for r in results if r.get('max_cvss', 0) >= 7)

        print(f"\n{Colors.BOLD}SCAN SUMMARY:{Colors.ENDC}")
        print(f"  {Colors.GRAY}├─{Colors.ENDC} Targets scanned     : {len(results)}")
        print(f"  {Colors.GRAY}├─{Colors.ENDC} Header findings      : {Colors.FAIL if total_hdr  else Colors.GRAY}{total_hdr}{Colors.ENDC}")
        print(f"  {Colors.GRAY}├─{Colors.ENDC} Body findings        : {Colors.FAIL if total_body else Colors.GRAY}{total_body}{Colors.ENDC}")
        print(f"  {Colors.GRAY}└─{Colors.ENDC} High/Critical hosts  : {Colors.FAIL if high_count else Colors.OKGREEN}{high_count}{Colors.ENDC}")
        print(f"{Colors.PURPLE}{'═'*W}{Colors.ENDC}\n")

# ============================================================================
# INTERACTIVE MENU
# ============================================================================

def get_input(prompt):
    try:
        return input(prompt).strip()
    except (KeyboardInterrupt, EOFError):
        print(f"\n{Colors.GRAY}Cancelled{Colors.ENDC}")
        return None

def get_targets(target_type="URL"):
    print(f"\n{Colors.BOLD}[INPUT]{Colors.ENDC}")
    print(f"  [1] Single {target_type}")
    print(f"  [2] File (one per line)")
    choice = get_input(f"\n{Colors.BOLD}Select [1-2] > {Colors.ENDC}")
    if not choice:
        return None
    if choice == '2':
        filepath = get_input(f"{Colors.BOLD}File path > {Colors.ENDC}")
        if not filepath or not os.path.isfile(filepath):
            print(f"{Colors.FAIL}File not found{Colors.ENDC}")
            return None
        with open(filepath) as f:
            targets = [l.strip() for l in f if l.strip() and not l.startswith('#')]
        print(f"{Colors.OKGREEN}Loaded {len(targets)} targets{Colors.ENDC}")
        return targets
    else:
        target = get_input(f"{Colors.BOLD}Target > {Colors.ENDC}")
        return [target] if target else None

def interactive_menu():
    print_main_banner()
    while True:
        print_tool_menu()
        choice = get_input(f"{Colors.BOLD}{Colors.PURPLE}Select [0-5] > {Colors.ENDC}")
        if not choice:
            continue

        if choice == '0':
            print(f"\n{Colors.GRAY}Goodbye!{Colors.ENDC}")
            break

        elif choice == '1':
            targets = get_targets("URL")
            if targets:
                checker = SecurityHeadersChecker()
                print(f"\n{Colors.OKCYAN}Scanning {len(targets)} target(s)...{Colors.ENDC}")
                checker.print_batch_summary([checker.check_url(t) for t in targets])

        elif choice == '2':
            targets = get_targets("Domain")
            if targets:
                scanner = DNSRecon()
                print(f"\n{Colors.OKCYAN}Scanning {len(targets)} target(s)...{Colors.ENDC}")
                scanner.print_batch_summary([scanner.check_domain(t) for t in targets])

        elif choice == '3':
            targets = get_targets("URL")
            if targets:
                checker = HTTPMethodsChecker()
                print(f"\n{Colors.OKCYAN}Scanning {len(targets)} target(s)...{Colors.ENDC}")
                checker.print_batch_summary([checker.check_url(t) for t in targets])

        elif choice == '4':
            targets = get_targets("URL")
            if targets:
                scanner = InfoDisclosureScanner()
                print(f"\n{Colors.OKCYAN}Scanning {len(targets)} target(s)...{Colors.ENDC}")
                scanner.print_batch_summary([scanner.scan_url(t) for t in targets])

        elif choice == '5':
            targets = get_targets("URL")
            if targets:
                print(f"\n{Colors.PURPLE}{'═'*115}{Colors.ENDC}")
                print(f"{Colors.BOLD}{Colors.PURPLE}FULL SCAN — ALL MODULES{Colors.ENDC}")
                print(f"{Colors.PURPLE}{'═'*115}{Colors.ENDC}")

                print(f"\n{Colors.OKCYAN}[1/4] Security Headers...{Colors.ENDC}")
                c = SecurityHeadersChecker()
                c.print_batch_summary([c.check_url(t) for t in targets])

                print(f"{Colors.OKCYAN}[2/4] DNS Reconnaissance...{Colors.ENDC}")
                domains = list({urlparse(t if t.startswith('http') else f'https://{t}').netloc for t in targets})
                d = DNSRecon()
                d.print_batch_summary([d.check_domain(dom) for dom in domains])

                print(f"{Colors.OKCYAN}[3/4] HTTP Methods & CORS...{Colors.ENDC}")
                h = HTTPMethodsChecker()
                h.print_batch_summary([h.check_url(t) for t in targets])

                print(f"{Colors.OKCYAN}[4/4] Information Disclosure...{Colors.ENDC}")
                i = InfoDisclosureScanner()
                i.print_batch_summary([i.scan_url(t) for t in targets])

                print(f"{Colors.OKGREEN}Full scan complete!{Colors.ENDC}\n")

        else:
            print(f"{Colors.FAIL}Invalid choice{Colors.ENDC}")

def main():
    parser = argparse.ArgumentParser(description=f'Low Hanging Fruit Web Security Toolkit v{__version__}')
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    args = parser.parse_args()
    interactive_menu()

if __name__ == "__main__":
    main()
