# axios-checker-py

Developer machine triage script for the **axios npm supply chain compromise** (March 31, 2026).

Checks your local machine and project directories for all known indicators of compromise from the `axios@1.14.1` / `axios@0.30.4` attack — including compromised lockfiles, the trojan dependency, RAT artifacts, active C2 connections, and cached malicious tarballs.

> **Advisory ID:** SCSA-2026-0331-AXS  
> **Severity:** CRITICAL  
> **Safe versions:** `axios@1.14.0` (1.x) · `axios@0.30.3` (0.x)

---

## Background

On March 31, 2026, two malicious versions of `axios` were published to npm via a compromised maintainer account:

- `axios@1.14.1` — targeting the current 1.x branch
- `axios@0.30.4` — targeting the legacy 0.x branch

The attacker injected a single trojan transitive dependency — `plain-crypto-js@4.2.1` — which executes a cross-platform **Remote Access Trojan (RAT) dropper** via npm's `postinstall` lifecycle hook. No user interaction is required. Any project using `^1.14.0` or `^0.30.0` that ran `npm install` after **2026-03-31 00:21 UTC** is potentially compromised.

The attack bypassed GitHub Actions CI/CD and SLSA provenance attestations entirely. No axios source files were modified, making the compromise invisible to standard code review.

**References:**
- SafeDep analysis: https://safedep.io/axios-npm-supply-chain-compromise/
- StepSecurity analysis: https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan

---

## Requirements

- Python 3.6+
- No third-party dependencies — stdlib only
- Works on macOS, Linux, and Windows

---

## Usage

```bash
# Download and run
curl -O https://raw.githubusercontent.com/YOUR_ORG/axios-compromise-checker/main/main.py
python3 main.py
```

Or clone the repo:

```bash
git clone https://github.com/YOUR_ORG/axios-compromise-checker.git
cd axios-compromise-checker
python3 main.py
```

The script requires no elevated privileges. It does not make any network requests itself — all checks are local only.

---

## What It Checks

| # | Check | What It Does |
|---|-------|-------------|
| 1 | **npm versions** | Runs `npm list axios` locally and globally; flags `1.14.1` and `0.30.4` |
| 2 | **Lockfile scan** | Recursively scans `~/` for `package-lock.json` files containing compromised axios versions using regex-precise matching (v1 and v2/v3 lockfile formats) |
| 3 | **Trojan package** | Searches for any `plain-crypto-js` directory under your home directory |
| 4 | **Payload hash** | Finds any `setup.js` in `node_modules` matching the trojan SHA256 |
| 5 | **Filesystem artifacts** | Checks all known RAT drop paths per OS |
| 6 | **Network** | Checks active connections to the C2 IP and domain via `netstat`/`ss` |
| 7 | **Shell history** | Scans `.bash_history`, `.zsh_history`, and others for C2 references |
| 8 | **npm cache** | Scans your npm cache directory for cached malicious tarballs |

### Platform-Specific Artifacts Checked

| Platform | Artifact Path |
|----------|--------------|
| All | `$TMPDIR/6202033` |
| Linux | `/tmp/ld.py` |
| macOS | `/Library/Caches/com.apple.act.mond` |
| Windows | `%PROGRAMDATA%\wt.exe` |

---

## Sample Output

**Clean machine:**
```
╔══════════════════════════════════════════════════════════════╗
║   axios Supply Chain Compromise — Triage Script             ║
║   Advisory SCSA-2026-0331-AXS  |  March 31, 2026            ║
╚══════════════════════════════════════════════════════════════╝

  OS      : Darwin 25.3.0
  Python  : 3.14.3
  Home    : /Users/yourname

── npm — installed axios versions ─────────────────────────────
  [OK]   axios not found (local)
  [OK]   axios not found (global)

── Project lockfiles — scanning for compromised versions ───────
  [OK]   Scanned 12 lockfile(s) — no compromised axios versions found

── node_modules — scanning for plain-crypto-js ─────────────────
  [OK]   plain-crypto-js not found in node_modules

── setup.js — checking for trojan payload by hash ──────────────
  [OK]   No trojan setup.js found by hash

── Filesystem — known RAT artifacts ────────────────────────────
  [OK]   Not present: /tmp/6202033
  [OK]   Not present: /Library/Caches/com.apple.act.mond

── Network — active C2 connections ─────────────────────────────
  [OK]   No active connections to 142.11.206.73 / sfrclak.com

── Shell history — C2 domain references ────────────────────────
  [OK]   No C2 references found in shell history

── npm cache — checking for cached malicious tarballs ──────────
  [OK]   No compromised tarballs found in npm cache

═══════════════════════════════════════════════════════════════
  RESULT: NO INDICATORS FOUND — MACHINE APPEARS CLEAN
═══════════════════════════════════════════════════════════════
```

**Compromised machine:**
```
── Project lockfiles — scanning for compromised versions ───────
  [HIT]  axios@1.14.1 found in lockfile
         /Users/yourname/myproject/package-lock.json

── Filesystem — known RAT artifacts ────────────────────────────
  [HIT]  Artifact found: /Library/Caches/com.apple.act.mond

═══════════════════════════════════════════════════════════════
  RESULT: 2 INDICATOR(S) FOUND — POSSIBLE COMPROMISE
═══════════════════════════════════════════════════════════════

  Immediate actions required:
  1. Pin axios to safe version:
       npm install axios@1.14.0   # 1.x
       npm install axios@0.30.3   # 0.x
  2. Rotate ALL credentials on this machine
       - npm tokens, SSH keys, cloud credentials, API keys
  3. Block at firewall/VPN: 142.11.206.73:8000 / sfrclak.com
  4. Report findings to your security team immediately
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No indicators found — machine appears clean |
| `1` | One or more indicators found — investigate immediately |

The exit code makes it suitable for use in MDM scripts, onboarding checks, or CI pre-flight gates.

---

## Indicators of Compromise (IoC)

| Indicator | Type |
|-----------|------|
| `axios@1.14.1` | Malicious npm package |
| `axios@0.30.4` | Malicious npm package |
| `plain-crypto-js@4.2.1` | Trojan dependency (RAT dropper) |
| `sfrclak[.]com:8000` | C2 domain |
| `142.11.206.73` | C2 IP address |
| `hxxp://sfrclak[.]com:8000/6202033` | C2 second-stage URL |
| `/tmp/ld.py` | Linux — second-stage Python RAT |
| `/Library/Caches/com.apple.act.mond` | macOS — RAT persistence path |
| `%PROGRAMDATA%\wt.exe` | Windows — renamed PowerShell binary |
| `$TMPDIR/6202033` | All platforms — staging file |
| `ifstap@proton[.]me` | Threat actor (compromised axios maintainer account) |
| `nrwise@proton[.]me` | Threat actor (`plain-crypto-js` publisher) |

**Trojan payload hash:**
```
setup.js  SHA256: e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09
```

---

## If You Find a Hit

1. **Do not dismiss it** — report to your security team immediately
2. **Pin axios** in the affected project:
   ```bash
   npm install axios@1.14.0   # 1.x branch
   npm install axios@0.30.3   # 0.x branch
   ```
3. **Rotate all credentials** on the affected machine:
   - npm tokens
   - SSH keys
   - Cloud credentials (AWS, GCP, Azure)
   - API keys and secrets
   - CI/CD environment variables
4. **Block at network perimeter:** `sfrclak.com` and `142.11.206.73:8000`
5. **Preserve evidence** — do not reboot or wipe before your security team has triaged

---

## False Positive Note

The lockfile scanner uses regex-precise matching anchored to the `axios` package entry specifically — it will not flag other packages that happen to share the version number `1.14.1` or `0.30.4`. Both npm lockfile v1 and v2/v3 formats are handled.

If the script reports a hit on a lockfile, verify by opening the file and searching for `"node_modules/axios"` (v2/v3) or `"axios":` (v1) and confirming the version field reads `1.14.1` or `0.30.4`.

---

## License

MIT

---

## Contributing

This script was written in response to an active incident. If you find issues or have improvements — particularly for edge cases in lockfile parsing or Windows artifact paths — PRs are welcome.

Please do not open issues to discuss whether the advisory itself is accurate; refer to the SafeDep and StepSecurity analyses linked above.
