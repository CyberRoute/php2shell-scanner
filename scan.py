#!/usr/bin/env python3
"""
php2shell-scanner — CVE-2026-109618 / CVE-2026-109619 vulnerability validator.

Non-destructive detector for the PHP session.upload_progress injection chain.

It never executes code on the target. Confirmation is done with an INERT random
canary: a unique token is written into a session file through the upload_progress
filename, then — only if you supply an LFI/file-read endpoint — read back over
HTTP and matched. Matching the canary proves the inject+include primitive (the
same primitive the repo's poc/ turns into RCE) without running anything.

Checks performed:
  1. Fingerprint  — PHP version from Server / X-Powered-By, mapped to the
                    affected/fixed table.
  2. Fixation     — is a POST-body PHPSESSID honored (session.use_only_cookies
                    = Off), letting an attacker choose the session id?
  3. upload_prog  — is the upload_progress multipart mechanism accepted (not
                    WAF-blocked / disabled)?
  4. Confirm      — (optional, needs --lfi) inject an inert canary and read it
                    back through the LFI to prove injection+inclusion.

Usage:
  python3 scan.py --target http://host:port
  python3 scan.py --target http://host:port \
      --session-path /index.php \
      --lfi 'http://host:port/vuln.php?page=FUZZ' \
      --save-path /tmp/sessions

AUTHORIZED TESTING ONLY. Run against systems you own or are explicitly
permitted to test. See README.md.
"""
import argparse
import re
import secrets
import socket
import sys
import urllib.request
from urllib.parse import urlparse

# ---- Affected-version table (from the advisory) ----------------------------
# Each stable branch is fixed at the version below; anything earlier in that
# branch is vulnerable. Branches not listed (8.1, 8.0, 7.x, 5.x) are EOL and
# treated as vulnerable when upload_progress exists.
BRANCH_FIX = {
    (8, 2): 35,
    (8, 3): 36,
    (8, 4): 27,
    (8, 5): 12,
}
EOL_VULNERABLE = {(8, 1), (8, 0), (7, 4), (7, 3), (7, 2), (7, 1), (7, 0),
                  (5, 6), (5, 5), (5, 4)}

RESET = "\033[0m"
def c(txt, col):
    cols = {"red": 31, "green": 32, "yellow": 33, "blue": 34, "grey": 90}
    return f"\033[{cols[col]}m{txt}{RESET}" if sys.stdout.isatty() else txt


def classify_version(ver):
    """Return (verdict, note) for a dotted PHP version string."""
    m = re.match(r"(\d+)\.(\d+)\.(\d+)", ver or "")
    if not m:
        return "unknown", "could not parse version"
    major, minor, patch = int(m[1]), int(m[2]), int(m[3])
    branch = (major, minor)
    if branch in BRANCH_FIX:
        fix = BRANCH_FIX[branch]
        if patch < fix:
            return "vulnerable", f"{ver} < {major}.{minor}.{fix} (patched)"
        return "patched", f"{ver} >= {major}.{minor}.{fix}"
    if branch in EOL_VULNERABLE:
        return "vulnerable", f"{major}.{minor}.x is end-of-life, no official fix"
    if major > 8 or (major == 8 and minor > 5):
        return "unknown", f"{ver} is newer than the advisory range"
    return "unknown", f"{ver} not in the advisory table"


# ---- Low-level HTTP ---------------------------------------------------------
def fingerprint(target, timeout):
    """GET the target root; return (status, headers dict, body bytes)."""
    req = urllib.request.Request(target, method="GET",
                                 headers={"User-Agent": "php2shell-scanner"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read(65536)
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read(65536)
    except Exception as e:
        return None, {"_error": str(e)}, b""


def upload_progress_post(host, port, path, sid, filename, send_cookie, timeout):
    """Send one upload_progress multipart POST over a raw socket.

    PHPSESSID is placed in the POST body (fixation probe); the cookie is sent
    only when send_cookie is True. Returns (status_line, body_bytes, set_cookie).
    """
    boundary = "SCAN" + secrets.token_hex(4)
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n{sid}\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="{filename}"\r\n\r\nZ\r\n'
        f"--{boundary}--\r\n"
    ).encode("latin-1")

    headers = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: php2shell-scanner\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {len(body)}\r\n"
    )
    if send_cookie:
        headers += f"Cookie: PHPSESSID={sid}\r\n"
    headers += "Connection: close\r\n\r\n"

    s = socket.create_connection((host, port), timeout=timeout)
    s.sendall(headers.encode() + body)
    s.settimeout(timeout)
    resp = b""
    while True:
        try:
            d = s.recv(65536)
            if not d:
                break
            resp += d
        except socket.timeout:
            break
    s.close()

    status = resp.split(b"\r\n", 1)[0].decode("latin1", "replace") if resp else "NO RESPONSE"
    head = resp.split(b"\r\n\r\n", 1)[0] if b"\r\n\r\n" in resp else resp
    body_out = resp.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in resp else b""
    m = re.search(rb"set-cookie:\s*(.*)", head, re.I)
    set_cookie = m.group(1).decode("latin1", "replace").strip() if m else ""
    return status, body_out, set_cookie


def lfi_read(lfi_template, file_path, timeout):
    """GET the LFI endpoint with FUZZ replaced by file_path; return body bytes."""
    url = lfi_template.replace("FUZZ", urllib.parse.quote(file_path, safe="/"))
    req = urllib.request.Request(url, headers={"User-Agent": "php2shell-scanner"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read(262144)
    except urllib.error.HTTPError as e:
        return e.read(262144)
    except Exception:
        return b""


# ---- Main -------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True, help="http://host:port")
    ap.add_argument("--session-path", default="/",
                    help="path to an endpoint that calls session_start() "
                         "(default '/')")
    ap.add_argument("--lfi", default=None,
                    help="LFI/file-read endpoint with FUZZ marker, e.g. "
                         "'http://h/vuln.php?page=FUZZ' — enables canary confirmation")
    ap.add_argument("--save-path", default=None,
                    help="session.save_path on the target; if omitted, a short "
                         "candidate list is tried for the canary read-back")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--yes", action="store_true",
                    help="confirm you are authorized to test this target")
    args = ap.parse_args()

    if not args.yes:
        print(c("Refusing to run without --yes (authorized-testing acknowledgement).",
                "yellow"))
        print("Only scan systems you own or have explicit written permission to test.")
        sys.exit(2)

    u = urlparse(args.target)
    host, port = u.hostname, (u.port or (443 if u.scheme == "https" else 80))
    if u.scheme == "https":
        print(c("[!] Raw-socket probes target plain HTTP; https targets need a "
                "TLS wrapper (not implemented here).", "yellow"))

    print(c("php2shell-scanner — CVE-2026-109618/109619", "blue"))
    print(f"[*] Target: {args.target}\n")

    results = {}

    # --- Check 1: fingerprint -----------------------------------------------
    status, headers, body = fingerprint(args.target, args.timeout)
    if status is None:
        print(c(f"[1] Fingerprint       FAIL — unreachable ({headers.get('_error')})",
                "red"))
        sys.exit(2)
    banner = headers.get("x-powered-by", "") or headers.get("server", "")
    vm = re.search(r"PHP/([\d.]+)", banner) or re.search(r"PHP ([\d.]+)", body.decode("latin1", "replace"))
    version = vm.group(1) if vm else None
    verdict, note = classify_version(version)
    results["version"] = verdict
    label = {"vulnerable": c("VULNERABLE", "red"), "patched": c("patched", "green"),
             "unknown": c("unknown", "yellow")}[verdict]
    print(f"[1] Fingerprint       PHP {version or '?'}  -> {label}")
    print(c(f"       {note}  (banner: {banner or 'none'})", "grey"))

    # --- Check 2: POST-body fixation ----------------------------------------
    sid_fix = "scanfix" + secrets.token_hex(10)
    try:
        st, _, setck = upload_progress_post(host, port, args.session_path,
                                            sid_fix, "canary.txt",
                                            send_cookie=False, timeout=args.timeout)
    except OSError as e:
        print(c(f"[2] Fixation          FAIL — connection error: {e}", "red"))
        st, setck = "", ""
    # If the server issues NO new Set-Cookie PHPSESSID, it accepted our body SID
    # (use_only_cookies=Off). A fresh server-chosen cookie means it rejected it.
    issued_new = bool(re.search(r"PHPSESSID=([^;]+)", setck)) and sid_fix not in setck
    fixation_ok = st.startswith("HTTP") and not issued_new
    results["fixation"] = fixation_ok
    print(f"[2] Fixation          {'OK  ' if fixation_ok else 'no  '}"
          f"POST-body PHPSESSID {'honored' if fixation_ok else 'not honored'} "
          f"{c('(use_only_cookies=Off)', 'grey') if fixation_ok else ''}")
    if setck:
        print(c(f"       Set-Cookie: {setck}", "grey"))

    # --- Check 3: upload_progress accepted ----------------------------------
    sid_up = "scanup" + secrets.token_hex(10)
    try:
        st3, _, _ = upload_progress_post(host, port, args.session_path,
                                         sid_up, "probe.txt",
                                         send_cookie=True, timeout=args.timeout)
    except OSError as e:
        st3 = f"ERR {e}"
    up_ok = st3.startswith("HTTP") and " 200" in st3
    results["upload_progress"] = up_ok
    print(f"[3] upload_progress   {'OK  ' if up_ok else 'no  '}"
          f"multipart probe -> {st3}")

    # --- Check 4: inert canary confirmation (optional) ----------------------
    confirmed = False
    if args.lfi:
        canary = "P2S_" + secrets.token_hex(12)          # inert, no PHP tags
        sid_can = "scancan" + secrets.token_hex(10)
        try:
            upload_progress_post(host, port, args.session_path, sid_can,
                                 canary, send_cookie=True, timeout=args.timeout)
        except OSError as e:
            print(c(f"[4] Confirm           FAIL — inject error: {e}", "red"))
        candidates = ([args.save_path] if args.save_path else
                      ["/tmp/sessions", "/var/lib/php/sessions",
                       "/var/lib/php/session", "/var/lib/php5", "/tmp"])
        hit_path = None
        for base in candidates:
            data = lfi_read(args.lfi, f"{base.rstrip('/')}/sess_{sid_can}", args.timeout)
            if canary.encode() in data:
                hit_path = base
                break
        confirmed = hit_path is not None
        results["confirm"] = confirmed
        if confirmed:
            print(c(f"[4] Confirm           CONFIRMED — canary read back from "
                    f"{hit_path}/sess_{sid_can}", "red"))
            print(c("       inert token injected via upload_progress was returned "
                    "through the LFI:", "grey"))
            print(c(f"       canary={canary}  (swap for <?php ?> = RCE; see poc/)", "grey"))
        else:
            print(f"[4] Confirm           no  — canary not read back "
                  f"(wrong --save-path, no LFI, or not injectable)")
    else:
        print(c("[4] Confirm           skipped — pass --lfi to prove the primitive", "grey"))

    # --- Verdict ------------------------------------------------------------
    print()
    if confirmed:
        v = c("VULNERABLE (confirmed)", "red")
        detail = "injection+inclusion primitive proven with an inert canary."
    elif results.get("version") == "vulnerable" and results.get("fixation") \
            and results.get("upload_progress"):
        v = c("LIKELY VULNERABLE", "red")
        detail = ("affected version + fixation + upload_progress all present; "
                  "supply --lfi to confirm end-to-end.")
    elif results.get("version") == "patched":
        v = c("LIKELY PATCHED", "green")
        detail = "PHP version is at or above the fixed release for its branch."
    elif results.get("upload_progress") or results.get("fixation"):
        v = c("PRECONDITIONS PRESENT", "yellow")
        detail = "some preconditions hold; version unclear or one check failed."
    else:
        v = c("NOT DETECTED", "green")
        detail = "no preconditions observed over HTTP."
    print(f"[=] Verdict: {v}")
    print(c(f"    {detail}", "grey"))
    print(c("    Mitigate: session.upload_progress.enabled=Off; "
            "use_only_cookies=On; patch PHP.", "grey"))

    sys.exit(0 if confirmed or results.get("version") == "vulnerable" else 1)


if __name__ == "__main__":
    main()
