# NGINX2Root: unauthenticated RCE in NGINX (CVE-2026-123633 and CVE-2026-123007)

## What it is

Two critical memory safety flaws in how NGINX handles HTTP/2 traffic, both
allowing an unauthenticated remote attacker to execute code on the NGINX
server. The flaws sit in NGINX itself, so a site can be exposed even when
the application behind it has no bug of its own. Wiz Research disclosed
them on 18 November 2026 after coordinated disclosure with F5. Four other
research teams (Ikotas Labs, Metnir, Rapid7, and Xint) found the same flaws
independently. Wiz calls the pair NGINX2Root.

CVE-2026-123633 is a use-after-free in HTTP/2 connection handling. When a
client sends only part of a HEADERS frame, NGINX marks the connection as
reusable while it waits for the rest. The rest of the frame then starts a
request, but the connection stays on the reusable list. When NGINX later
needs a free connection slot, for example while opening an upstream
connection to a backend, it can close and free that still active
connection. Request processing then continues using freed memory.

CVE-2026-123007 is an integer underflow in HTTP/2 flow control. NGINX
tracks how much response data it may send in a counter called
`send_window`. When a stream is cancelled while its data is still queued,
the unused allowance is returned to the counter. Faulty accounting lets
the counter underflow, which leads to an invalid memory copy and a heap
buffer overflow.

## Affected products and versions

NGINX Open Source and NGINX Plus, with HTTP/2 enabled. Both flaws require
HTTP/2. CVE-2026-123633 also requires the server to proxy requests to a
backend, and it bites when worker connections run low. CVE-2026-123007
can hit a server that only serves static files, with no backend and no
third party modules. Wiz demonstrated code execution that way on 64-bit
systems over HTTPS.

- CVE-2026-123007: NGINX OSS 1.9.5 to 1.31.8. The flaw dates back to 2015,
  so it sat in the code for more than a decade.
- CVE-2026-123633: NGINX OSS 1.19.7 to 1.31.8. It had been there for
  nearly six years.
- NGINX Plus: R33 and 37.0.0 onward for both, per the Wiz write-up.

The same F5 security release fixed eight more flaws, including three
other CVEs rated 9.2 under CVSS 4.0 (an HTTP/3 use-after-free,
CVE-2026-121810; a DNS resolver use-after-free, CVE-2026-123634; and a
mail proxy use-after-free, CVE-2026-113425), plus a TLS 1.3 infinite loop
rated 8.7. This lab focuses on the two HTTP/2 RCE flaws, which are the
ones with the widest reach.

## Severity

Both CVEs score 9.2 Critical under CVSS 4.0, and 8.1 High under CVSS 3.1,
according to NVD records retrieved 19 November 2026. Wiz rates both
Critical. Typical memory safety mitigations such as ASLR do not stop
these flaws, because an attacker can gain memory read access before
executing code.

## Exploitation status

As of 19 November 2026, no confirmed exploitation in the wild has been
reported in the sources checked. Wiz confirmed remote code execution with
an ASLR bypass for CVE-2026-123633 during its research, and demonstrated
code execution for CVE-2026-123007 on a server serving ordinary static
files. The disclosure is one day old, so exploitation attempts should be
expected to follow quickly. That is the pattern with flaws of this reach:
the window between disclosure and scanning is short.

## Why it matters

NGINX is the most widely used open source web server, powering more than
225 million websites according to Netcraft figures cited by Wiz. It is
usually the front door, handling HTTPS and routing traffic to the
applications behind it. One affected deployment can serve several
applications, so a single compromise can reach across multiple services
and their data. A successful exploit can run commands, steal sensitive
data, tamper with websites, or disrupt services.

There is a second lesson here. Wiz notes that these flaws, like the
PHP2Shell flaws reported last month and Java4Shell disclosed the day
before, are memory safety bugs that were hard to find for years because
they need careful tracing across several code paths. AI assisted code
scanning found them, and several independent teams found the same ones.
Flaws that used to stay hidden for a decade are now surfacing in
clusters, which shortens the time defenders have to patch.

## Detection ideas

- Inventory first. List every NGINX deployment, its version, whether
  HTTP/2 is enabled, and whether it proxies. The checker in this folder
  does exactly that against a fictional inventory.
- Watch for unexpected NGINX worker crashes or segmentation faults.
  CVE-2026-123007 typically ends in a worker crash when it does not lead
  to code execution, so a sudden rise in worker restarts after 18
  November is worth investigating.
- Watch for commands or child processes launched by an NGINX worker.
  Workers should not spawn shells.
- Review HTTP/2 traffic volume and error rates around the disclosure
  date for unusual patterns, such as many incomplete HEADERS frames or
  cancelled streams. Wiz notes these are general warning signs, not
  confirmed indicators for these flaws.
- No public proof of concept exploit was available in the sources
  checked, so there is no known exploit signature to match yet.

## Mitigation and patch guidance

- Upgrade NGINX OSS to 1.30.7 (stable) or 1.31.9 (mainline). Upgrade
  NGINX Plus to 37.0.7.1 or 37.2.0.1 for CVE-2026-123633, and 37.0.8.1
  or 37.3.0.1 for CVE-2026-123007. Prioritise internet facing
  deployments first.
- If you cannot upgrade right away, disable HTTP/2 as a temporary
  workaround. On NGINX 1.25.1 or later, set `http2 off;` in the affected
  server blocks and remove the `http2` parameter from listen directives.
  Then reload NGINX and confirm the old workers have exited. Re-enable
  HTTP/2 after upgrading.
- Disabling HTTP/2 is mitigation, not a fix. The vulnerable code stays
  in place, so upgrade as soon as the rollout is tested.

## Lab artifact

`check_nginx2root.py` is an exposure checker. It takes an NGINX version,
whether HTTP/2 is on, and whether the host proxies requests, then reports
PATCHED, EXPOSED, MITIGATED (HTTP/2 off), or NOT AFFECTED, naming the
applicable CVE for each host. It runs in single host mode and in fleet
mode against `sample_fleet.csv`, a fictional inventory of six hosts.
See the folder README for the captured output.

## Sources

- Wiz blog, "Unauthenticated Remote Code Execution in NGINX:
  CVE-2026-123633 and CVE-2026-123007", 18 November 2026.
  https://www.wiz.io/blog/nginx-http2-rce-vulnerabilities
- Xint blog, "NGINX2Root: Remote Code Execution Vulnerabilities in
  Nginx", 18 November 2026. https://xint.io/blog/nginx2root-remote-code-execution
- NVD records for CVE-2026-123633 and CVE-2026-123007, retrieved
  19 November 2026. CVSS 4.0 9.2 Critical, CVSS 3.1 8.1 High for both.
  https://nvd.nist.gov/vuln/detail/CVE-2026-123633
  https://nvd.nist.gov/vuln/detail/CVE-2026-123007
- Hacker News discussion, "Unauthenticated remote code execution in
  Nginx", 18 November 2026 (1,443 points at time of writing).
  https://news.ycombinator.com/item?id=50547374
- CISA alert, "Critical Java Vulnerability Requires Immediate Patching",
  17 November 2026, noted only because it covers the related Java4Shell
  disclosure from the previous day, not this one.
  https://www.cisa.gov/news-events/alerts/2026/11/17/critical-java-vulnerability-requires-immediate-patching

## What could not be verified

- NVD records for both CVEs were in "Received" status at the time of
  retrieval, with descriptions and scores present but full analysis
  still pending. Fixed release numbers and affected ranges come from
  the Wiz write-up of the F5 release.
- No public exploit code or confirmed in the wild exploitation was
  found in the sources checked. The exploitation status above reflects
  that, not a claim that exploitation has not happened.
- The NGINX vendor advisory page returned a 403 when fetched directly,
  so the F5 advisory itself was not read. Version and fix details are
  taken from Wiz and NVD.
