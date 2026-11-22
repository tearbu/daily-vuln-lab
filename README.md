# Daily Vuln Lab

A daily, hands-on study project. Each morning I look through the newly disclosed vulnerabilities that have surfaced on Hacker News, pick the most significant one, and build a small, focused lab on it. That might be a detection rule, a checker script, or a configuration analysis. I publish it here with a written analysis.

Everything is built from public sources and uses fictional sample data only. I run each artifact locally before publishing it. No exploit code is included.

## How an edition is built

Each edition follows the same routine. I scan the vulnerabilities disclosed on Hacker News over the previous day or so and pick the most significant one: a named CVE where there is one, a serious severity rating, wide product reach, signs of exploitation or a credible technical write-up, and a defensive angle that can be turned into a small lab. The pick is then checked against the NVD record and the vendor advisory, so the analysis rests on primary sources rather than the Hacker News thread alone. The folder for the edition gets an `analysis.md` covering what the vulnerability is, who is affected, how it works at the level public sources support, detection ideas, and patch guidance, plus one working artifact, usually a checker script.

### Decisions

- **One vulnerability a day, in depth, instead of a list.** A single edition can be read, built, and verified in one sitting. Ten summaries would be headlines with no working artifact behind any of them.
- **Defensive artifacts only.** The labs are exposure checkers, version and configuration checks, and detection material. No exploit code is written or included, and nothing in an edition helps run an attack.
- **Fictional sample data only.** Every checker runs against an invented fleet, device, or log file, so any reader can reproduce the result and nothing real is exposed. The trade-off is that a verdict describes the sample data, not a production estate.
- **Python standard library for the checkers.** The scripts run anywhere Python 3 does, with nothing to install. Each one is run locally before the edition is published, and its real output is captured in the edition folder.

## Worth and limits

The worth is the habit made visible: a dated public record of working through current vulnerabilities as they surface, with a running artifact for each one instead of notes that stay private. Building the checker is the part that teaches. Summarising a CVE is easy. Deciding how an organisation would know whether it is exposed, and writing the check that answers that, forces the practical questions about versions, configurations, and logs.

The limits are plain. These are one-sitting studies built from public sources, not assessments of any real environment, and the fictional data means an EXPOSED or PATCHED result is a demonstration. The 2026-11-21 edition carries its own example: its local reachability probe was inconclusive on the machine where the lab was built, because that machine's DNS resolver answers for any hostname, so the probe appeared to resolve a service that was not there. The edition README flags it rather than reporting a clean result. Where a source could not be verified, the analysis says that too.

## Editions

- 2026-11-13 | CVE-2026-119618, critical RCE in Apache HTTP Server mod_http2 | [2026-11-13-cve-2026-119618](2026-11-13-cve-2026-119618/)
- 2026-11-14 | Android clipboard read toast bypass, Moderate severity, Won't Fix | [2026-11-14-android-clipboard-toast-bypass](2026-11-14-android-clipboard-toast-bypass/)
- 2026-11-15 | Coruna iOS exploit kit delivered through hacked ads on Dutch news sites | [2026-11-15-coruna-ios-malvertising](2026-11-15-coruna-ios-malvertising/)
- 2026-11-16 | NoisyTCP, Linux kernel TCP pre-auth remote corruption, CVE-2026-99288 | [2026-11-16-cve-2026-99288](2026-11-16-cve-2026-99288/)
- 2026-11-17 | CVE-2026-90436, critical unauthenticated RCE in Apache Axis 1.x, exploited against Confluence Data Center and N-able N-central | [2026-11-17-cve-2026-90436](2026-11-17-cve-2026-90436/)
- 2026-11-18 | Java4Shell, pre-auth RCE in the OpenJDK Base64 decoder, CVE-2026-114938 | [2026-11-18-cve-2026-114938](2026-11-18-cve-2026-114938/)
- 2026-11-19 | NGINX2Root, unauthenticated RCE in NGINX, CVE-2026-123633 and CVE-2026-123007 | [2026-11-19-nginx2root](2026-11-19-nginx2root/)
- 2026-11-20 | CVE-2026-123890, unauthenticated authentication bypass in VMware vCenter, exploited as a zero-day by ARMORY CASTLE | [2026-11-20-cve-2026-123890](2026-11-20-cve-2026-123890/)
- 2026-11-21 | CVE-2026-28400, Docker Model Runner argument injection leading to container escape and host code execution | [2026-11-21-cve-2026-28400](2026-11-21-cve-2026-28400/)
- 2026-11-22 | CVE-2026-125396, Upload2Shell, Ghostscript use-after-free and -dSAFER bypass leading to RCE through file uploads | [2026-11-22-cve-2026-125396](2026-11-22-cve-2026-125396/)
