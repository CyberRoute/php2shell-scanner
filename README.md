# php2shell-scanner

Non-destructive validator for **CVE-2026-109618 / CVE-2026-109619** — the PHP
`session.upload_progress` filename-injection chain.

The POCs demonstrate full RCE; this scanner only **detects and confirms the vulnerability primitive**, so it is safe to point at an in-scope target to answer "is this host exploitable?".

## What it does

| # | Check            | Signal |
|---|------------------|--------|
| 1 | Fingerprint      | PHP version from `Server` / `X-Powered-By`, mapped to the fixed-release table |
| 2 | Fixation         | Is a POST-body `PHPSESSID` honored? (`session.use_only_cookies = Off`) |
| 3 | upload_progress  | Is the `PHP_SESSION_UPLOAD_PROGRESS` multipart mechanism accepted (not disabled / WAF-blocked)? |
| 4 | Confirm (opt-in) | Inject an **inert random canary** via the upload filename, then read it back through a supplied LFI and match it |

It **never executes code on the target.** Check 4 writes a harmless token like `P2S_da68fe7c...` (no `<?php` tags), reads it back, and matches the string. Matching proves the inject-and-include primitive — the exact point the `poc/`
repo swaps the token for a PHP payload to get RCE.

## Usage

```bash
# Preconditions only (version + fixation + upload_progress)
python3 scan.py --target http://host:port --session-path /index.php --yes

# Full end-to-end confirmation with an LFI endpoint
python3 scan.py \
  --target http://host:port \
  --session-path /index.php \
  --lfi 'http://host:port/vuln.php?page=FUZZ' \
  --save-path /tmp/sessions \
  --yes
```

- `--session-path` — any endpoint that calls `session_start()` (the session file
  is written during this request). Defaults to `/`.
- `--lfi` — a file-read/LFI endpoint with `FUZZ` where the file path goes.
  Without it, check 4 is skipped and the best verdict is *LIKELY VULNERABLE*.
- `--save-path` — the target's `session.save_path`. If omitted, a short
  candidate list (`/tmp/sessions`, `/var/lib/php/sessions`, …) is tried.
- `--yes` — required acknowledgement that you are authorized to test the target.

Stdlib-only; no dependencies. Plain HTTP only (no TLS wrapper yet).

## Verdicts

| Verdict | Meaning |
|---------|---------|
| `VULNERABLE (confirmed)` | canary injected and read back — primitive proven |
| `LIKELY VULNERABLE` | affected version + fixation + upload_progress, no LFI supplied to confirm |
| `PRECONDITIONS PRESENT` | some signals hold; version unclear or one check failed |
| `LIKELY PATCHED` | PHP version is at/above the fixed release for its branch |
| `NOT DETECTED` | no preconditions observed |

Exit code `0` when confirmed or version is in the affected range, else `1`
(`2` = unreachable / refused).

## Fixed releases

`8.2.35`, `8.3.36`, `8.4.27`, `8.5.12`. Branches 8.1/8.0/7.x/5.x are EOL and
treated as vulnerable where `upload_progress` exists.

## Mitigation

```ini
session.upload_progress.enabled = Off
session.use_only_cookies = On
```
…and patch PHP to the fixed release for your branch.

## Disclaimer

For authorized security testing and educational use only. Do not scan systems
you do not own or lack explicit written permission to test. Tested on https://github.com/ikow/php2shell-poc
