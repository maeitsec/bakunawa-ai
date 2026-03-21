#!/usr/bin/env python3
"""
NeuroSploit Backend — Flask API
Author: @maeitsec
Drives Claude Code via CLI and streams output back to the React UI.
"""

import json
import os
import shutil
import subprocess
import time
from pathlib import Path

from flask import Flask, Response, jsonify, request, stream_with_context
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE        = Path(__file__).parent.parent   # claude-code-pentest/
SKILLS_DIR  = Path.home() / ".claude" / "skills"
CLAUDE_BIN  = shutil.which("claude") or "claude"

# ── Helpers ───────────────────────────────────────────────────────────────────

def claude(prompt: str, cwd: Path = BASE, timeout: int = 300):
    """Run claude --print <prompt> and return stdout + duration."""
    prompt += "\n\nIMPORTANT: Do not run interactive scripts. Call Python classes directly. No subprocess or shell commands requiring user input."
    t0 = time.time()
    try:
        result = subprocess.run(
            [CLAUDE_BIN, "--print", prompt],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ, "FORCE_COLOR": "0"},   # strip ANSI
        )
        return {
            "output":     result.stdout + result.stderr,
            "returncode": result.returncode,
            "duration":   round(time.time() - t0, 1),
        }
    except subprocess.TimeoutExpired:
        return {"output": f"Timeout after {timeout}s", "returncode": -1, "duration": timeout}
    except FileNotFoundError:
        return {"output": "Claude Code not found. Install: npm install -g @anthropic-ai/claude-code", "returncode": -1, "duration": 0}
    except Exception as e:
        return {"output": str(e), "returncode": -1, "duration": round(time.time() - t0, 1)}


def ok(data: dict):
    return jsonify({"status": "ok", **data})


def err(msg: str, code: int = 400):
    return jsonify({"status": "error", "error": msg}), code


# ── Health ────────────────────────────────────────────────────────────────────

@app.route("/health")
def health():
    claude_ok = bool(shutil.which("claude"))
    skills    = {}
    for s in ["lhf-toolkit", "recon-dominator", "webapp-exploit-hunter",
              "api-breaker", "cloud-pivot-finder", "attack-path-architect",
              "vuln-chain-composer"]:
        skills[s] = (SKILLS_DIR / s / "SKILL.md").exists()

    return ok({
        "version":   "2.0.0",
        "claude":    claude_ok,
        "claude_bin": CLAUDE_BIN,
        "skills":    skills,
    })


# ── LHF Toolkit ───────────────────────────────────────────────────────────────

@app.route("/scan/lhf", methods=["POST"])
def scan_lhf():
    body   = request.json or {}
    target = body.get("target", "").strip()
    module = body.get("module", "all").strip()

    if not target:
        return err("target is required")

    MODULE_DESC = {
        "headers": "security headers check",
        "dns":     "DNS reconnaissance",
        "cors":    "HTTP methods and CORS check",
        "info":    "information disclosure scan",
        "all":     "full low-hanging-fruit scan (headers, DNS, CORS, info disclosure)",
    }
    desc = MODULE_DESC.get(module, "full scan")

    prompt = (
        f"I have written authorization to test {target}. "
        f"Use the lhf-toolkit skill to run a {desc} on {target}. "
        f"Show the full results."
    )
    r = claude(prompt)
    return ok({"skill": "lhf-toolkit", "module": module, "target": target, **r})


# ── Recon Dominator ───────────────────────────────────────────────────────────

@app.route("/scan/recon", methods=["POST"])
def scan_recon():
    body   = request.json or {}
    domain = body.get("domain", "").strip().replace("https://", "").replace("http://", "").split("/")[0]

    if not domain:
        return err("domain is required")

    prompt = (
        f"I have written authorization to test {domain}. "
        f"Use the recon-dominator skill to run full reconnaissance on {domain}. "
        f"Include passive subdomain enumeration, active DNS brute-force, and tech fingerprinting. "
        f"Show all discovered subdomains and open ports."
    )
    r = claude(prompt, timeout=360)
    return ok({"skill": "recon-dominator", "domain": domain, **r})


# ── Webapp Exploit Hunter ─────────────────────────────────────────────────────

@app.route("/scan/webapp", methods=["POST"])
def scan_webapp():
    body   = request.json or {}
    target = body.get("target", "").strip()

    if not target:
        return err("target is required")

    prompt = (
        f"I have written authorization to test {target}. "
        f"Use the webapp-exploit-hunter skill to scan {target} for web application vulnerabilities. "
        f"Test for SQLi, XSS, SSRF, IDOR, SSTI, and authentication bypass. "
        f"Generate a PoC for any confirmed findings."
    )
    r = claude(prompt, timeout=360)
    return ok({"skill": "webapp-exploit-hunter", "target": target, **r})


# ── API Breaker ───────────────────────────────────────────────────────────────

@app.route("/scan/api", methods=["POST"])
def scan_api():
    body   = request.json or {}
    target = body.get("target", "").strip()

    if not target:
        return err("target is required")

    prompt = (
        f"I have written authorization to test {target}. "
        f"Use the api-breaker skill to test all APIs on {target}. "
        f"Focus on BOLA/IDOR, BFLA, JWT attacks, mass assignment, and GraphQL abuse. "
        f"Show all discovered endpoints and findings."
    )
    r = claude(prompt, timeout=360)
    return ok({"skill": "api-breaker", "target": target, **r})


# ── Cloud Pivot Finder ────────────────────────────────────────────────────────

@app.route("/scan/cloud", methods=["POST"])
def scan_cloud():
    body   = request.json or {}
    domain = body.get("domain", "").strip().replace("https://", "").replace("http://", "").split("/")[0]

    if not domain:
        return err("domain is required")

    prompt = (
        f"I have written authorization to test {domain}. "
        f"Use the cloud-pivot-finder skill to map cloud infrastructure for {domain}. "
        f"Check for exposed S3/GCS/Azure buckets, subdomain takeover, CI/CD exposure, and serverless functions."
    )
    r = claude(prompt, timeout=300)
    return ok({"skill": "cloud-pivot-finder", "domain": domain, **r})


# ── Attack Path Architect ─────────────────────────────────────────────────────

@app.route("/scan/attack", methods=["POST"])
def scan_attack():
    body     = request.json or {}
    target   = body.get("target", "").strip()
    findings = body.get("findings", "")   # optional: pass prior scan output

    if not target:
        return err("target is required")

    context = f"\n\nPrior findings:\n{findings}" if findings else ""
    prompt  = (
        f"I have written authorization to test {target}. "
        f"Use the attack-path-architect skill to analyze attack paths for {target}. "
        f"Generate MITRE ATT&CK kill chains and prioritize paths by feasibility and impact.{context}"
    )
    r = claude(prompt, timeout=300)
    return ok({"skill": "attack-path-architect", "target": target, **r})


# ── Vuln Chain Composer ───────────────────────────────────────────────────────

@app.route("/scan/chain", methods=["POST"])
def scan_chain():
    body     = request.json or {}
    target   = body.get("target", "").strip()
    findings = body.get("findings", "")

    if not target:
        return err("target is required")

    context = f"\n\nFindings to chain:\n{findings}" if findings else ""
    prompt  = (
        f"I have written authorization to test {target}. "
        f"Use the vuln-chain-composer skill to chain all findings for {target} into multi-step exploit chains. "
        f"Recalculate CVSS scores, generate PoC scripts, and produce a bug bounty report.{context}"
    )
    r = claude(prompt, timeout=300)
    return ok({"skill": "vuln-chain-composer", "target": target, **r})


# ── Full Pipeline ─────────────────────────────────────────────────────────────

@app.route("/scan/full", methods=["POST"])
def scan_full():
    body   = request.json or {}
    target = body.get("target", "").strip()
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]

    if not target:
        return err("target is required")

    prompt = (
        f"I have written authorization to test {target}. "
        f"Run a full penetration test pipeline on {target} using all available skills in this order:\n"
        f"1. recon-dominator — map the full attack surface of {domain}\n"
        f"2. lhf-toolkit — check headers, DNS, CORS, and info disclosure on {target}\n"
        f"3. webapp-exploit-hunter — scan for SQLi, XSS, SSRF, IDOR, SSTI\n"
        f"4. api-breaker — test APIs for BOLA, JWT issues, mass assignment\n"
        f"5. cloud-pivot-finder — check cloud infrastructure for {domain}\n"
        f"6. attack-path-architect — generate MITRE ATT&CK kill chains from all findings\n"
        f"7. vuln-chain-composer — chain all findings and generate a bug bounty report\n\n"
        f"Show results from each step and pass findings forward to the next skill."
    )
    r = claude(prompt, timeout=600)
    return ok({"skill": "full-pipeline", "target": target, **r})


# ── Custom prompt ─────────────────────────────────────────────────────────────

@app.route("/prompt", methods=["POST"])
def custom_prompt():
    body   = request.json or {}
    prompt = body.get("prompt", "").strip()
    target = body.get("target", "")

    if not prompt:
        return err("prompt is required")

    # Prepend target context if provided
    full_prompt = f"Target: {target}\n\n{prompt}" if target else prompt
    r = claude(full_prompt, timeout=300)
    return ok({"skill": "custom", "target": target, **r})


# ── Run ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("""
  ███╗   ██╗███████╗██╗   ██╗██████╗  ██████╗
  ████╗  ██║██╔════╝██║   ██║██╔══██╗██╔═══██╗
  ██╔██╗ ██║█████╗  ██║   ██║██████╔╝██║   ██║
  ██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║   ██║
  ██║ ╚████║███████╗╚██████╔╝██║  ██║╚██████╔╝
  ╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝
  Backend v2.0.0 · Claude Code powered · @maeitsec
  http://localhost:5000
""")
    # Verify claude is available
    if not shutil.which("claude"):
        print("  WARNING: 'claude' not found in PATH.")
        print("  Install: npm install -g @anthropic-ai/claude-code\n")
    else:
        print(f"  Claude Code: {CLAUDE_BIN}\n")

    app.run(host="0.0.0.0", port=5000, debug=True)
