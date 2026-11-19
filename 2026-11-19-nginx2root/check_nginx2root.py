#!/usr/bin/env python3
"""NGINX2Root exposure checker (CVE-2026-123633 and CVE-2026-123007).

Reads an NGINX version and a few config facts and judges whether a host
is exposed to the two critical unauthenticated RCE flaws disclosed
18 November 2026. It checks version ranges, whether HTTP/2 is on, and
whether the host proxies requests, since CVE-2026-123633 only applies
to proxy setups. It does not probe a live server and contains no
exploit code. All sample data is fictional.

Usage:
    python3 check_nginx2root.py single --version 1.25.3 --http2 on --role proxy
    python3 check_nginx2root.py fleet sample_fleet.csv
"""

import argparse
import csv
import sys

# Affected ranges from the Wiz write-up of the F5 security release.
# CVE-2026-123007: NGINX OSS 1.9.5 through 1.31.8
# CVE-2026-123633: NGINX OSS 1.19.7 through 1.31.8
# Fixed releases: 1.30.7 (stable) and 1.31.9 (mainline).
FIXED_STABLE = (1, 30, 7)
FIXED_MAINLINE = (1, 31, 9)
RANGE_123007 = ((1, 9, 5), (1, 31, 8))
RANGE_123633 = ((1, 19, 7), (1, 31, 8))


def parse_version(text):
    parts = text.strip().split(".")
    if len(parts) != 3:
        raise ValueError("version must look like 1.25.3, got %r" % text)
    return tuple(int(p) for p in parts)


def is_fixed(version):
    major, minor, patch = version
    if (major, minor) == (1, 30):
        return patch >= FIXED_STABLE[2]
    if (major, minor) == (1, 31):
        return patch >= FIXED_MAINLINE[2]
    if (major, minor) > (1, 31):
        return True
    return False


def in_range(version, low, high):
    return low <= version <= high


def assess(version_text, http2, role):
    version = parse_version(version_text)
    http2_on = http2.strip().lower() in ("on", "yes", "true", "enabled")
    is_proxy = role.strip().lower() == "proxy"

    if is_fixed(version):
        return {
            "version": version_text,
            "cves": [],
            "verdict": "PATCHED",
            "detail": "version is at or above a fixed release (1.30.7 stable or 1.31.9 mainline)",
        }

    cves = []
    if in_range(version, *RANGE_123007):
        cves.append("CVE-2026-123007")
    if is_proxy and in_range(version, *RANGE_123633):
        cves.append("CVE-2026-123633")

    if not cves:
        return {
            "version": version_text,
            "cves": [],
            "verdict": "NOT AFFECTED",
            "detail": "version is outside the affected ranges for both CVEs",
        }

    if not http2_on:
        return {
            "version": version_text,
            "cves": cves,
            "verdict": "MITIGATED (HTTP/2 off)",
            "detail": "version is vulnerable but HTTP/2 is disabled, which removes the attack path; upgrade anyway",
        }

    return {
        "version": version_text,
        "cves": cves,
        "verdict": "EXPOSED",
        "detail": "vulnerable version with HTTP/2 enabled; upgrade to 1.30.7 or 1.31.9, or disable HTTP/2 now",
    }


def cmd_single(args):
    result = assess(args.version, args.http2, args.role)
    print("NGINX2Root (CVE-2026-123633, CVE-2026-123007) single-host check")
    print("=" * 62)
    print("Version: %s" % result["version"])
    print("HTTP/2: %s" % args.http2)
    print("Role: %s" % args.role)
    print("Applicable CVEs: %s" % (", ".join(result["cves"]) or "none"))
    print("Verdict: %s" % result["verdict"])
    print("Note: %s" % result["detail"])
    return 0


def cmd_fleet(args):
    print("NGINX2Root (CVE-2026-123633, CVE-2026-123007) fleet check")
    print("=" * 62)
    counts = {}
    try:
        with open(args.csv, newline="") as handle:
            rows = list(csv.DictReader(handle))
    except FileNotFoundError:
        print("error: file not found: %s" % args.csv, file=sys.stderr)
        return 2

    for row in rows:
        result = assess(row["nginx_version"], row["http2"], row["role"])
        counts[result["verdict"]] = counts.get(result["verdict"], 0) + 1
        print(
            "%-22s %-9s http2=%-3s %-7s -> %s (%s)"
            % (
                row["host"],
                row["nginx_version"],
                row["http2"],
                row["role"],
                result["verdict"],
                ", ".join(result["cves"]) or "no applicable CVE",
            )
        )

    print("-" * 62)
    print("Summary: %d hosts checked" % len(rows))
    for verdict in sorted(counts):
        print("  %s: %d" % (verdict, counts[verdict]))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    single = sub.add_parser("single", help="check one host")
    single.add_argument("--version", required=True, help="e.g. 1.25.3")
    single.add_argument("--http2", required=True, choices=["on", "off"])
    single.add_argument("--role", required=True, choices=["proxy", "static"])
    single.set_defaults(func=cmd_single)

    fleet = sub.add_parser("fleet", help="check a CSV inventory")
    fleet.add_argument("csv", help="CSV with host, nginx_version, http2, role")
    fleet.set_defaults(func=cmd_fleet)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
