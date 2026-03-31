#!/usr/bin/env python3
"""
axios Supply Chain Compromise — Developer Machine Triage Script
Advisory: SCSA-2026-0331-AXS
Date: March 31, 2026

Checks for indicators of compromise from the axios@1.14.1 / 0.30.4
supply chain attack on the current machine.

Run with: python3 axios_triage.py
No dependencies beyond Python 3 stdlib.
"""

import os
import re
import sys
import json
import shutil
import hashlib
import platform
import subprocess
from pathlib import Path

# ── Constants ────────────────────────────────────────────────────────────────

COMPROMISED_VERSIONS = {"1.14.1", "0.30.4"}
TROJAN_PACKAGE       = "plain-crypto-js"
SETUP_JS_HASH        = "e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09"
C2_DOMAIN            = "sfrclak.com"
C2_IP                = "142.11.206.73"

ARTIFACTS = {
    "linux":   ["/tmp/ld.py"],
    "darwin":  ["/Library/Caches/com.apple.act.mond"],
    "windows": [os.path.join(os.environ.get("PROGRAMDATA", "C:\\ProgramData"), "wt.exe")],
    "all":     [os.path.join(os.environ.get("TMPDIR", os.environ.get("TMP", "/tmp")), "6202033")],
}

# ── Helpers ───────────────────────────────────────────────────────────────────

BOLD   = "\033[1m"
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"

# Disable color on Windows unless ANSICON / WT
if platform.system() == "Windows" and not os.environ.get("WT_SESSION"):
    BOLD = RED = GREEN = YELLOW = CYAN = RESET = ""

findings = []

def banner():
    print(f"""
{BOLD}{RED}╔══════════════════════════════════════════════════════════════╗
║   axios Supply Chain Compromise — Triage Script              ║
║   Advisory SCSA-2026-0331-AXS  |  March 31, 2026             ║
╚══════════════════════════════════════════════════════════════╝{RESET}
""")

def section(title):
    print(f"\n{BOLD}{CYAN}── {title} {'─' * (55 - len(title))}{RESET}")

def hit(label, detail=""):
    tag = f"{RED}{BOLD}[HIT]{RESET}"
    msg = f"  {tag}  {label}"
    if detail:
        msg += f"\n         {YELLOW}{detail}{RESET}"
    print(msg)
    findings.append({"check": label, "detail": detail})

def ok(label):
    print(f"  {GREEN}[OK]{RESET}   {label}")

def warn(label, detail=""):
    tag = f"{YELLOW}{BOLD}[WARN]{RESET}"
    msg = f"  {tag} {label}"
    if detail:
        msg += f"\n         {detail}"
    print(msg)

def run(cmd, shell=False):
    try:
        result = subprocess.run(
            cmd, shell=shell, capture_output=True, text=True, timeout=15
        )
        return result.stdout.strip(), result.returncode
    except Exception:
        return "", 1

def sha256_file(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

# ── Check 1: npm list — local and global axios versions ──────────────────────

def check_npm_versions():
    section("npm — installed axios versions")

    if not shutil.which("npm"):
        warn("npm not found in PATH — skipping npm checks")
        return

    for scope, flag in [("local", []), ("global", ["-g"])]:
        out, rc = run(["npm", "list", "axios", "--json", "--depth=0"] + flag)
        if not out:
            ok(f"axios not installed ({scope})")
            continue
        try:
            data = json.loads(out)
            deps = data.get("dependencies", {})
            axios = deps.get("axios", {})
            version = axios.get("version", "unknown")
            if version in COMPROMISED_VERSIONS:
                hit(f"axios@{version} installed ({scope})",
                    f"COMPROMISED VERSION — pin to 1.14.0 or 0.30.3 immediately")
            elif version != "unknown":
                ok(f"axios@{version} ({scope}) — not a compromised version")
            else:
                ok(f"axios not found ({scope})")
        except json.JSONDecodeError:
            # Fallback: parse plain text output
            for line in out.splitlines():
                if "axios@" in line:
                    ver = line.split("axios@")[-1].strip()
                    if ver in COMPROMISED_VERSIONS:
                        hit(f"axios@{ver} installed ({scope})",
                            "COMPROMISED VERSION — pin to 1.14.0 or 0.30.3 immediately")
                    else:
                        ok(f"axios@{ver} ({scope}) — not a compromised version")

# ── Check 2: Scan project directories for package-lock.json hits ─────────────

def lockfile_axios_version(content):
    """
    Return the compromised axios version string if found, else None.
    Handles both lockfile v1 and v2/v3 formats precisely.
    Uses regex to avoid false positives from other packages at the same version.
    """
    patterns = [
        # v2/v3: "node_modules/axios": { ... "version": "1.14.1"
        r'"node_modules/axios"\s*:\s*\{[^}]*?"version"\s*:\s*"(1\.14\.1|0\.30\.4)"',
        # v1:    "axios": { "version": "1.14.1"
        r'"axios"\s*:\s*\{\s*"version"\s*:\s*"(1\.14\.1|0\.30\.4)"',
    ]
    for pattern in patterns:
        m = re.search(pattern, content, re.DOTALL)
        if m:
            return m.group(1)
    return None

def check_lockfiles():
    section("Project lockfiles — scanning for compromised versions")

    search_roots = [Path.home()]
    # Common project dirs
    for candidate in ["Projects", "projects", "dev", "Dev", "code", "Code",
                      "workspace", "Workspace", "src", "repos"]:
        p = Path.home() / candidate
        if p.is_dir():
            search_roots.append(p)

    scanned = 0
    hits = []

    for root in search_roots:
        for lockfile in root.rglob("package-lock.json"):
            # Skip node_modules
            if "node_modules" in lockfile.parts:
                continue
            scanned += 1
            try:
                content = lockfile.read_text(errors="ignore")
                ver = lockfile_axios_version(content)
                if ver:
                    hits.append((str(lockfile), ver))
                    hit(f"axios@{ver} found in lockfile", str(lockfile))
                if TROJAN_PACKAGE in content:
                    hit(f"plain-crypto-js referenced in lockfile", str(lockfile))
            except Exception:
                continue

    if scanned == 0:
        warn("No package-lock.json files found under home directory")
    elif not hits:
        ok(f"Scanned {scanned} lockfile(s) — no compromised axios versions found")
    else:
        pass  # already printed hits above

# ── Check 3: plain-crypto-js in node_modules ─────────────────────────────────

def check_trojan_package():
    section(f"node_modules — scanning for {TROJAN_PACKAGE}")

    found = []
    for path in Path.home().rglob("plain-crypto-js"):
        if path.is_dir():
            found.append(path)

    if found:
        for p in found:
            hit(f"plain-crypto-js directory found", str(p))
    else:
        ok("plain-crypto-js not found in node_modules")

# ── Check 4: setup.js hash ────────────────────────────────────────────────────

def check_setup_js():
    section("setup.js — checking for trojan payload by hash")

    found = []
    for path in Path.home().rglob("setup.js"):
        if "node_modules" not in path.parts:
            continue
        digest = sha256_file(path)
        if digest == SETUP_JS_HASH:
            found.append(path)
            hit("Trojan setup.js found (hash match)",
                f"Path: {path}\nSHA256: {digest}")

    if not found:
        ok("No trojan setup.js found by hash")

# ── Check 5: Filesystem artifacts ────────────────────────────────────────────

def check_artifacts():
    section("Filesystem — known RAT artifacts")

    system = platform.system().lower()
    paths_to_check = ARTIFACTS["all"][:]

    if system == "linux":
        paths_to_check += ARTIFACTS["linux"]
    elif system == "darwin":
        paths_to_check += ARTIFACTS["darwin"]
    elif system == "windows":
        paths_to_check += ARTIFACTS["windows"]

    found_any = False
    for p in paths_to_check:
        if os.path.exists(p):
            found_any = True
            hit(f"Artifact found: {p}")
        else:
            ok(f"Not present: {p}")

    if not found_any:
        pass  # ok() already printed per-path

# ── Check 6: Network — active C2 connections ──────────────────────────────────

def check_network():
    section("Network — active C2 connections")

    system = platform.system().lower()
    c2_found = False

    if system == "windows":
        out, _ = run(["netstat", "-an"])
    else:
        out, _ = run(["netstat", "-an"])
        if not out:
            out, _ = run(["ss", "-tn"])

    if out:
        for line in out.splitlines():
            if C2_IP in line or C2_DOMAIN in line:
                hit(f"Active C2 connection detected", line.strip())
                c2_found = True
        if not c2_found:
            ok(f"No active connections to {C2_IP} / {C2_DOMAIN}")
    else:
        warn("Could not run netstat/ss — check network manually")
        warn(f"Look for connections to: {C2_IP} or {C2_DOMAIN}:8000")

# ── Check 7: Shell history ────────────────────────────────────────────────────

def check_shell_history():
    section("Shell history — C2 domain references")

    history_files = [
        Path.home() / ".bash_history",
        Path.home() / ".zsh_history",
        Path.home() / ".sh_history",
        Path.home() / ".history",
    ]

    found_any = False
    for hf in history_files:
        if not hf.exists():
            continue
        try:
            content = hf.read_text(errors="ignore")
            if C2_DOMAIN in content or C2_IP in content:
                found_any = True
                hit(f"C2 reference in shell history", str(hf))
        except Exception:
            continue

    if not found_any:
        ok(f"No C2 references found in shell history")

# ── Check 8: npm cache ────────────────────────────────────────────────────────

def check_npm_cache():
    section("npm cache — checking for cached malicious tarballs")

    if not shutil.which("npm"):
        return

    cache_dir, rc = run(["npm", "config", "get", "cache"])
    if rc != 0 or not cache_dir:
        warn("Could not determine npm cache directory")
        return

    cache_path = Path(cache_dir.strip())
    if not cache_path.exists():
        ok("npm cache directory not found")
        return

    found = []
    for pattern in ["axios-1.14.1", "axios-0.30.4", "plain-crypto-js"]:
        matches = list(cache_path.rglob(f"*{pattern}*"))
        for m in matches:
            found.append((pattern, m))
            hit(f"Cached malicious tarball: {pattern}", str(m))

    if not found:
        ok(f"No compromised tarballs found in npm cache ({cache_path})")

# ── Summary ───────────────────────────────────────────────────────────────────

def summary():
    print(f"\n{BOLD}{'═' * 63}{RESET}")
    if findings:
        print(f"{BOLD}{RED}  RESULT: {len(findings)} INDICATOR(S) FOUND — POSSIBLE COMPROMISE{RESET}")
        print(f"{BOLD}{'═' * 63}{RESET}\n")
        print(f"{YELLOW}  Immediate actions required:{RESET}")
        print(f"  1. Pin axios to safe version:")
        print(f"       npm install axios@1.14.0   # 1.x")
        print(f"       npm install axios@0.30.3   # 0.x")
        print(f"  2. Rotate ALL credentials on this machine")
        print(f"       - npm tokens, SSH keys, cloud credentials, API keys")
        print(f"  3. Block at firewall/VPN: {C2_IP}:8000 / {C2_DOMAIN}")
        print(f"  4. Report findings to your security team immediately")
        print(f"\n  {BOLD}Findings summary:{RESET}")
        for i, f in enumerate(findings, 1):
            print(f"    {i}. {f['check']}")
            if f["detail"]:
                print(f"       {YELLOW}{f['detail']}{RESET}")
    else:
        print(f"{BOLD}{GREEN}  RESULT: NO INDICATORS FOUND — MACHINE APPEARS CLEAN{RESET}")
        print(f"{BOLD}{'═' * 63}{RESET}\n")
        print(f"  Recommended precaution: pin axios in your projects")
        print(f"    npm install axios@1.14.0")
    print(f"\n  Advisory: SCSA-2026-0331-AXS")
    print(f"  Reference: https://safedep.io/axios-npm-supply-chain-compromise/")
    print()

# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    banner()
    print(f"  OS      : {platform.system()} {platform.release()}")
    print(f"  Python  : {sys.version.split()[0]}")
    print(f"  Home    : {Path.home()}")

    check_npm_versions()
    check_lockfiles()
    check_trojan_package()
    check_setup_js()
    check_artifacts()
    check_network()
    check_shell_history()
    check_npm_cache()
    summary()

    sys.exit(1 if findings else 0)

if __name__ == "__main__":
    main()

