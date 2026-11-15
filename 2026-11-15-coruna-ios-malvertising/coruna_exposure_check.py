#!/usr/bin/env python3
"""Coruna iOS malvertising exposure checker.

Two small checks, both using only the Python standard library:

1. Device check: reads a CSV inventory of iPhones and iPads
   (columns: device, ios_version) and flags every device whose iOS
   version is below the fixed version for its branch. The version
   rules come from Apple's security bulletins for the Coruna exploit
   kit backports (see analysis.md for sources).

2. Log scan: reads a web access log and flags requests that match the
   data harvesting pattern described in the November 2026 Dutch
   malvertising incident: ad tag requests that carry device
   fingerprint details (screen size, language, operating system,
   referrer) to a third party host.

Usage:
    python3 coruna_exposure_check.py devices sample_inventory.csv
    python3 coruna_exposure_check.py log sample_ad_traffic.log

All sample data in this folder is fictional and was made up for this
lab. No exploit code is included.
"""

import csv
import re
import sys
from urllib.parse import parse_qs, urlparse


# Minimum safe version per iOS branch, with the Coruna CVEs each
# branch was exposed to. Sources: Apple security bulletins for
# iOS 15.8.7, iPadOS 15.8.7, iOS 16.7.15 and iPadOS 16.7.15
# (11 March 2026), the CVE.org records for the four CVEs, and
# Ostorlab's write-up of the APT29 watering hole chains for the
# 18.x line (CVE-2025-43529 fixed in iOS 18.7.3).
SAFE_VERSIONS = {
    15: ("15.8.7",
         ["CVE-2023-41974", "CVE-2024-23222",
          "CVE-2023-43000", "CVE-2023-43010"]),
    16: ("16.7.15", ["CVE-2023-43010"]),
    17: ("17.3", ["CVE-2024-23222", "CVE-2023-43010"]),
    18: ("18.7.3", ["CVE-2025-43529"]),
    26: ("26.3", ["CVE-2025-43529", "CVE-2026-20700"]),
}

# Branches Apple never backported a Coruna fix to. The kit is
# reported to target iOS 13.0 through 17.2.1.
NO_FIX_BRANCHES = (13, 14)


def parse_version(text):
    parts = text.strip().split(".")
    try:
        return tuple(int(p) for p in parts)
    except ValueError:
        return None


def version_str(version):
    return ".".join(str(p) for p in version)


def check_device(device, ios_version):
    """Return (status, detail) for one device."""
    version = parse_version(ios_version)
    if version is None:
        return "UNKNOWN", "version string did not parse: %s" % ios_version
    major = version[0]
    if major in NO_FIX_BRANCHES:
        return ("VULNERABLE",
                "iOS %s has no published Coruna backport for this "
                "branch; the kit is reported to target iOS 13.0 "
                "through 17.2.1" % ios_version)
    if major not in SAFE_VERSIONS:
        return ("UNKNOWN",
                "no Coruna version rule recorded for iOS %s" % major)
    safe_text, cves = SAFE_VERSIONS[major]
    safe = parse_version(safe_text)
    if version < safe:
        return ("VULNERABLE",
                "below %s; exposed to %s"
                % (safe_text, ", ".join(cves)))
    return ("OK", "at or above %s" % safe_text)


def device_check(path):
    print("Device exposure check: %s" % path)
    print("-" * 64)
    counts = {"VULNERABLE": 0, "OK": 0, "UNKNOWN": 0}
    with open(path, newline="") as handle:
        for row in csv.DictReader(handle):
            device = row["device"]
            version = row["ios_version"]
            status, detail = check_device(device, version)
            counts[status] += 1
            print("[%s] %s (iOS %s): %s" % (status, device, version, detail))
    print("-" * 64)
    print("Summary: %d vulnerable, %d ok, %d unknown"
          % (counts["VULNERABLE"], counts["OK"], counts["UNKNOWN"]))
    return 0 if counts["VULNERABLE"] == 0 else 1


# Fingerprint parameters the Dutch incident report says the malicious
# ad tag sent to the attacker server: IP address, visited page,
# referrer, screen size, language, operating system.
FINGERPRINT_PARAMS = ("screen", "sw", "sh", "lang", "os", "ref",
                      "referrer", "ua", "tz")

AD_TAG_HINTS = ("adtag", "ads", "adserver", "banner", "creative",
                "doubleclick", "adnxs", "taboola", "outbrain")


def scan_log(path):
    print("Ad traffic log scan: %s" % path)
    print("-" * 64)
    flagged = 0
    total = 0
    with open(path) as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            total += 1
            match = re.search(r'"(?:GET|POST)\s+(\S+)\s+HTTP', line)
            if not match:
                continue
            url = match.group(1)
            parsed = urlparse(url)
            host = parsed.netloc.lower()
            query = parse_qs(parsed.query)
            fingerprint_hits = [p for p in query
                                if p.lower() in FINGERPRINT_PARAMS]
            looks_like_ad = any(h in host for h in AD_TAG_HINTS)
            if looks_like_ad and len(fingerprint_hits) >= 2:
                flagged += 1
                print("[FLAG] %s" % line)
                print("       ad host %s sent fingerprint fields: %s"
                      % (host, ", ".join(sorted(fingerprint_hits))))
    print("-" * 64)
    print("Summary: %d of %d requests flagged as ad tag fingerprinting"
          % (flagged, total))
    return 0 if flagged == 0 else 1


def main(argv):
    if len(argv) != 3 or argv[1] not in ("devices", "log"):
        print(__doc__)
        print("Usage: coruna_exposure_check.py devices <csv>")
        print("       coruna_exposure_check.py log <access log>")
        return 2
    if argv[1] == "devices":
        return device_check(argv[2])
    return scan_log(argv[2])


if __name__ == "__main__":
    sys.exit(main(sys.argv))
