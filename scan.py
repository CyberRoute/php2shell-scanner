#!/usr/bin/env python3
"""
php2shell-scanner — CVE-2026-109618 / CVE-2026-109619 exposure detector.

Non-destructive detector for the two PHP "php2shell" vulnerabilities fixed in
the PHP October 2026 security release (2026-10-21):

  * CVE-2026-109618 — RCE via OOM corruption   (GHSA-w8hw-w9fx-j79w)
  * CVE-2026-109619 — RCE via stale global state (GHSA-6wmf-4rv5-p3rp)

Both are memory-corruption / use-after-free bugs. The real exploit forces a
*controllable fatal* (memory_limit exhaustion via crafted multipart bodies)
that interrupts native code before cleanup, leaving dangling pointers / stale
global state that a second request reclaims into an RCE primitive. See
https://calif.io/php2shell/ for the full write-up.

WHAT THIS TOOL DOES AND DOES NOT DO
-----------------------------------
There is no safe, non-destructive way to *actively confirm* these bugs: the
trigger stage is an intentional out-of-memory fatal, i.e. a denial-of-service,
and the follow-up reclaims corrupted heap. This scanner therefore DELIBERATELY
does not attempt to trigger, exhaust memory, or exploit anything. It only reads
passive signals and benign preconditions and reasons about exposure:

  1. Fingerprint  — PHP version from Server / X-Powered-By (or body), mapped to
                    the October-2026 fixed-release table.
  2. SAPI         — mod_php (Apache) vs PHP-FPM (nginx/fastcgi) vs unknown. Both
                    CVEs apply; the SAPI only changes which internal path is hit.
  3. Preconditions— is PHP session handling reachable (Set-Cookie PHPSESSID)
                    and is a multipart POST accepted? These are necessary (not
                    sufficient) for the stale-global-state path.

The verdict is driven mainly by the PHP version, because that is the only
reliable, non-destructive signal for a memory-corruption bug.

Usage:
  python3 scan.py --target http://host:port --yes
  python3 scan.py --target http://host:port --session-path /index.php --yes

AUTHORIZED TESTING ONLY. Run only against systems you own or are explicitly
permitted to test. See README.md.
"""
import argparse
import re
import secrets
import socket
import sys
import urllib.error
import urllib.request
from urllib.parse import urlparse

# ---- Fixed-release table (PHP October 2026 security release) ----------------
# Each active branch is fixed at the version below; anything earlier in that
# branch is vulnerable. 8.1 and older received no official release — only
# minimal source backports exist — so they are treated as vulnerable.
BRANCH_FIX = {
    (8, 2): 35,
    (8, 3): 36,
    (8, 4): 27,
    (8, 5): 12,
}
# Branches with no fixed release. The page states the earliest affected path
# dates back to PHP 5.4.0, so every EOL branch at/after 5.4 is exposed.
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
            return "vulnerable", f"{ver} < {major}.{minor}.{fix} (Oct-2026 fix)"
        return "patched", f"{ver} >= {major}.{minor}.{fix}"
    if branch in EOL_VULNERABLE:
        return "vulnerable", (f"{major}.{minor}.x is end-of-life; no official "
                              f"fixed release (only source backports)")
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


def detect_sapi(headers, body):
    """Best-effort mod_php vs PHP-FPM guess from passive response signals.

    Returns (sapi, note). The two CVEs apply to both SAPIs; this only indicates
    which internal code path (request-shutdown vs worker-exit / Basic RINIT) the
    write-up describes for this deployment.
    """
    server = (headers.get("server", "") or "").lower()
    powered = (headers.get("x-powered-by", "") or "").lower()
    if "mod_php" in server or re.search(r"php/[\d.]+", server):
        return "mod_php", f"Apache mod_php signature in Server: {headers.get('server')}"
    if "apache" in server and powered.startswith("php"):
        # Apache can also proxy to FPM; mod_php exposes PHP in Server more often.
        return "apache", f"Apache + X-Powered-By PHP (mod_php or proxied FPM): {headers.get('server')}"
    if "nginx" in server:
        return "fpm?", f"nginx front-end (PHP typically served via PHP-FPM): {headers.get('server')}"
    if powered.startswith("php"):
        return "unknown", f"PHP present (X-Powered-By) but SAPI not distinguishable"
    return "unknown", "no SAPI-identifying headers"


def multipart_probe(host, port, path, sid, timeout):
    """Send ONE benign upload_progress multipart POST over a raw socket.

    This is a single small, well-formed request. It does NOT bypass
    post_max_size, does NOT inflate memory, and does NOT attempt to force a
    fatal — it only checks that the server accepts a multipart POST carrying a
    PHP_SESSION_UPLOAD_PROGRESS field (a precondition of the stale-global-state
    path). Returns (status_line, set_cookie).
    """
    boundary = "SCAN" + secrets.token_hex(4)
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nscan\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="probe.txt"\r\n\r\nZ\r\n'
        f"--{boundary}--\r\n"
    ).encode("latin-1")

    headers = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: php2shell-scanner\r\n"
        f"Cookie: PHPSESSID={sid}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    )

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
    m = re.search(rb"set-cookie:\s*(.*)", head, re.I)
    set_cookie = m.group(1).decode("latin1", "replace").strip() if m else ""
    return status, set_cookie


# ---- Main -------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True, help="http://host:port")
    ap.add_argument("--session-path", default="/",
                    help="path to an endpoint that calls session_start() "
                         "(default '/')")
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
        print(c("[!] Raw-socket probe targets plain HTTP; https targets need a "
                "TLS wrapper (not implemented here) — only checks 1/2 will run.",
                "yellow"))

    print(c("php2shell-scanner — CVE-2026-109618 (OOM corruption) / "
            "CVE-2026-109619 (stale global state)", "blue"))
    print(f"[*] Target: {args.target}\n")

    results = {}

    # --- Check 1: version fingerprint ---------------------------------------
    status, headers, body = fingerprint(args.target, args.timeout)
    if status is None:
        print(c(f"[1] Fingerprint       FAIL — unreachable ({headers.get('_error')})",
                "red"))
        sys.exit(2)
    banner = headers.get("x-powered-by", "") or headers.get("server", "")
    vm = re.search(r"PHP/([\d.]+)", banner) or \
        re.search(r"PHP ([\d.]+)", body.decode("latin1", "replace"))
    version = vm.group(1) if vm else None
    verdict, note = classify_version(version)
    results["version"] = verdict
    label = {"vulnerable": c("VULNERABLE", "red"), "patched": c("patched", "green"),
             "unknown": c("unknown", "yellow")}[verdict]
    print(f"[1] Fingerprint       PHP {version or '?'}  -> {label}")
    print(c(f"       {note}  (banner: {banner or 'none'})", "grey"))
    if version is None:
        print(c("       version not advertised — the verdict cannot rely on it; "
                "patch regardless if PHP is in use.", "grey"))

    # --- Check 2: SAPI ------------------------------------------------------
    sapi, sapi_note = detect_sapi(headers, body)
    results["sapi"] = sapi
    print(f"[2] SAPI              {sapi}")
    print(c(f"       {sapi_note}", "grey"))
    print(c("       both CVEs apply to mod_php and PHP-FPM; the SAPI only "
            "changes the internal path.", "grey"))

    # --- Check 3: benign preconditions --------------------------------------
    # Only attempt the raw-socket multipart probe over plain HTTP.
    multipart_ok = None
    session_seen = bool(re.search(r"PHPSESSID=", headers.get("set-cookie", "") or ""))
    if u.scheme != "https":
        sid = "scan" + secrets.token_hex(10)
        try:
            st3, setck = multipart_probe(host, port, args.session_path, sid,
                                         args.timeout)
            multipart_ok = st3.startswith("HTTP")
            if re.search(r"PHPSESSID=", setck or ""):
                session_seen = True
            print(f"[3] Preconditions     multipart POST -> {st3}")
            if setck:
                print(c(f"       Set-Cookie: {setck}", "grey"))
        except OSError as e:
            print(c(f"[3] Preconditions     probe error: {e}", "red"))
    else:
        print(c("[3] Preconditions     skipped (https; raw-socket probe is "
                "plain-HTTP only)", "grey"))
    results["session"] = session_seen
    print(c(f"       PHP session handling observed: "
            f"{'yes' if session_seen else 'not seen'}  "
            f"(precondition for the stale-global-state path, CVE-2026-109619)",
            "grey"))

    # --- Verdict ------------------------------------------------------------
    print()
    if results.get("version") == "vulnerable":
        v = c("LIKELY VULNERABLE", "red")
        detail = ("PHP version is below the October-2026 fixed release for its "
                  "branch. These are unauthenticated-RCE memory-corruption bugs "
                  "exploitable under default config — patch now.")
    elif results.get("version") == "patched":
        v = c("LIKELY PATCHED", "green")
        detail = "PHP version is at or above the fixed release for its branch."
    elif version is None and (results.get("session") or multipart_ok):
        v = c("UNDETERMINED (PHP present, version hidden)", "yellow")
        detail = ("PHP is in use but the version is not advertised; exposure "
                  "cannot be judged remotely. Confirm the build and patch.")
    else:
        v = c("UNDETERMINED", "yellow")
        detail = "could not establish the PHP version from this host."
    print(f"[=] Verdict: {v}")
    print(c(f"    {detail}", "grey"))
    print(c("    Note: active confirmation requires forcing an out-of-memory "
            "fatal (a DoS) and reclaiming corrupted heap; this tool does not "
            "do that. Version is the reliable signal.", "grey"))
    print(c("    Mitigate (temporary, NOT a substitute for patching):", "grey"))
    print(c("      PHP-FPM:  session.upload_progress.enabled=0 ; memory_limit=-1", "grey"))
    print(c("      mod_php:  memory_limit=-1", "grey"))
    print(c("      memory_limit=-1 removes PHP's memory cap and raises "
            "exhaustion risk — upgrade to a fixed release instead.", "grey"))

    sys.exit(0 if results.get("version") == "vulnerable" else 1)


if __name__ == "__main__":
    main()
