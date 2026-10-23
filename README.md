# php2shell-scanner

Non-destructive **exposure detector** for **CVE-2026-109618 / CVE-2026-109619** —
the two PHP "php2shell" vulnerabilities fixed in the PHP October 2026 security
release (2026-10-21).

| CVE | Name |
|-----|------|
| CVE-2026-109618 | RCE via **OOM corruption** (GHSA-w8hw-w9fx-j79w) |
| CVE-2026-109619 | RCE via **stale global state** (GHSA-6wmf-4rv5-p3rp) |

Both are unauthenticated-RCE **memory-corruption / use-after-free** bugs,
exploitable under default configuration, with an affected code path reaching
back to PHP 5.4.0. See the write-up: <https://calif.io/php2shell/>.

## How the real bug works (and why confirmation is destructive)

The exploit has two stages:

1. **Force a controllable fatal.** A crafted multipart body (e.g. HTTP/1.1
   chunked or HTTP/2 lengthless requests that slip past `post_max_size`, plus
   hundreds of empty-filename upload parts with deeply nested field names that
   each expand into many `$_FILES` HashTables) exhausts `memory_limit` and
   triggers a fatal **inside native code, before cleanup runs.**
2. **Reclaim the stale state.** The interrupted path leaves a dangling pointer
   or stale global (a partially-initialised hash bucket, the session
   upload-progress state, or the `unserialize` decoder state). A follow-up
   request reclaims that freed heap into an RCE primitive.

Stage 1 is, by construction, an **out-of-memory denial-of-service**, and stage 2
reclaims corrupted heap. There is **no safe, non-destructive way to actively
confirm** these bugs on a live target. **This tool deliberately does not attempt
to trigger, exhaust memory, or exploit anything.** It reasons about *exposure*
from passive signals and benign preconditions only.

## What it does

| # | Check | Signal |
|---|-------|--------|
| 1 | Fingerprint   | PHP version from `Server` / `X-Powered-By` (or body), mapped to the Oct-2026 fixed-release table — the reliable signal |
| 2 | SAPI          | mod_php (Apache) vs PHP-FPM (nginx) vs unknown — context only; both CVEs apply to both |
| 3 | Preconditions | Is PHP session handling reachable (`Set-Cookie: PHPSESSID`) and is a single benign multipart POST accepted? Necessary — not sufficient — for the stale-global-state path |

The check-3 probe is **one small, well-formed request**. It does not bypass
`post_max_size`, does not inflate memory, and does not try to force a fatal.

## Usage

```bash
python3 scan.py --target http://host:port --yes
python3 scan.py --target http://host:port --session-path /index.php --yes
```

- `--session-path` — any endpoint that calls `session_start()` (default `/`).
- `--yes` — required acknowledgement that you are authorized to test the target.
- `--timeout` — per-request timeout in seconds (default 10).

Stdlib-only; no dependencies. The raw-socket precondition probe is plain-HTTP
only (no TLS wrapper yet); against `https://` targets, only checks 1 and 2 run.

## Verdicts

| Verdict | Meaning |
|---------|---------|
| `LIKELY VULNERABLE` | PHP version is below the Oct-2026 fixed release for its branch |
| `LIKELY PATCHED` | PHP version is at/above the fixed release for its branch |
| `UNDETERMINED` | PHP version could not be established remotely — judge from the build and patch regardless |

Exit code `0` when the version is in the affected range, else `1`
(`2` = unreachable / refused).

## Fixed releases (PHP October 2026 security release, 2026-10-21)

`8.2.35`, `8.3.36`, `8.4.27`, `8.5.12`. PHP **8.1 and older receive no official
fixed release** (only minimal source backports) and are treated as vulnerable
wherever PHP is in use.

## Mitigation

Patching is the only real fix. The upstream temporary mitigations are partial
and come with a warning that they do **not** replace a patch:

```ini
; PHP-FPM
session.upload_progress.enabled = 0
memory_limit = -1

; mod_php
memory_limit = -1
```

`memory_limit = -1` removes PHP's memory cap and *increases* exhaustion risk, so
upgrade to a fixed release instead of relying on it.

## Disclaimer

For authorized security testing and educational use only. Do not scan systems
you do not own or lack explicit written permission to test.
