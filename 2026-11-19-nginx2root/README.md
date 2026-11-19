# 2026-11-19: NGINX2Root, CVE-2026-123633 and CVE-2026-123007

Two critical memory safety flaws in NGINX's HTTP/2 handling, both
allowing unauthenticated remote code execution. Both score 9.2 Critical
under CVSS 4.0. CVE-2026-123633 is a use-after-free that needs a proxy
setup; CVE-2026-123007 is a flow control integer underflow that can hit
a server serving only static files. The flaws were disclosed 18 November
2026 by Wiz Research after coordinated disclosure with F5, and four
other teams found them independently. No confirmed exploitation in the
wild was reported in the sources checked as of 19 November 2026.

The lab artifact is `check_nginx2root.py`, an exposure checker. It reads
an NGINX version, whether HTTP/2 is on, and whether the host proxies
requests, then reports PATCHED, EXPOSED, MITIGATED (HTTP/2 off), or NOT
AFFECTED, naming the applicable CVE for each host. It runs in single
host mode and in fleet mode against `sample_fleet.csv`, a fictional
inventory of six hosts.

## How to run it

```
python3 check_nginx2root.py single --version 1.25.3 --http2 on --role proxy
python3 check_nginx2root.py fleet sample_fleet.csv
```

## Captured output, run 19 November 2026

Single host check, NGINX 1.25.3 proxying with HTTP/2 on:

```
NGINX2Root (CVE-2026-123633, CVE-2026-123007) single-host check
==============================================================
Version: 1.25.3
HTTP/2: on
Role: proxy
Applicable CVEs: CVE-2026-123007, CVE-2026-123633
Verdict: EXPOSED
Note: vulnerable version with HTTP/2 enabled; upgrade to 1.30.7 or 1.31.9, or disable HTTP/2 now
```

Fleet check against the fictional sample inventory:

```
NGINX2Root (CVE-2026-123633, CVE-2026-123007) fleet check
==============================================================
edge-proxy-01          1.25.3    http2=on  proxy   -> EXPOSED (CVE-2026-123007, CVE-2026-123633)
web-static-02          1.27.1    http2=on  static  -> EXPOSED (CVE-2026-123007)
api-gw-03              1.30.7    http2=on  proxy   -> PATCHED (no applicable CVE)
legacy-cdn-04          1.25.3    http2=off proxy   -> MITIGATED (HTTP/2 off) (CVE-2026-123007, CVE-2026-123633)
edge-proxy-05          1.31.9    http2=on  proxy   -> PATCHED (no applicable CVE)
old-intranet-06        1.18.0    http2=on  static  -> EXPOSED (CVE-2026-123007)
--------------------------------------------------------------
Summary: 6 hosts checked
  EXPOSED: 3
  MITIGATED (HTTP/2 off): 1
  PATCHED: 2
```

Note the last row: 1.18.0 predates CVE-2026-123633, but it is still in
range for CVE-2026-123007, which reaches back to 1.9.5. Old does not
mean safe here.

See `analysis.md` for the full write-up, with sources and what could
not be verified.
