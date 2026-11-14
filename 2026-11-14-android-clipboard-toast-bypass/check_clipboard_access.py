#!/usr/bin/env python3
"""Check which apps on an Android device can read the clipboard.

Reads a JSON description of a device (the kind of output you get from
`adb shell cmd appops query-op --user 0 READ_CLIPBOARD allow` plus the
device's Android version) and reports the clipboard exposure for each app.

This is a study tool. The sample files in this folder are fictional.
Point it at real `adb` output from your own device for a real audit.

Usage:
    python3 check_clipboard_access.py sample_device.json

Exit code 0 means no high risk app was found. Exit code 1 means at
least one third party app can read the clipboard.
"""

import json
import sys

# Android 10 (API 29) blocked background clipboard reads. Android 12
# (API 31) added the toast that shows when an app reads clipboard data
# copied by another app. The disclosure this lab covers shows that toast
# can be hidden by an app firing its own toasts first.
BACKGROUND_BLOCK_API = 29
TOAST_API = 31


def toast_status(api_level):
    if api_level >= TOAST_API:
        return (
            "toast shown on clipboard read (Android 12 and later), "
            "but a malicious app can hide that toast, see analysis.md"
        )
    if api_level >= BACKGROUND_BLOCK_API:
        return "no toast on clipboard read (Android 10 and 11)"
    return "no toast, and background apps can read the clipboard (before Android 10)"


def risk_for(app):
    mode = app.get("read_clipboard", "default")
    kind = app.get("kind", "third-party")
    if mode == "ignore":
        return ("OK", "clipboard read is blocked for this app")
    if mode == "default":
        return (
            "UNKNOWN",
            "mode is the system default, confirm it on the device with "
            "`adb shell cmd appops get <package> READ_CLIPBOARD`",
        )
    if mode != "allow":
        return ("UNKNOWN", "unrecognised mode %r" % mode)
    if kind == "keyboard":
        return (
            "MEDIUM",
            "a keyboard needs clipboard access to paste, but it can also "
            "read anything you copy, so it is worth trusting",
        )
    if kind == "system":
        return (
            "MEDIUM",
            "a system app with clipboard access, expected on most devices",
        )
    return (
        "HIGH",
        "a third party app that can read anything you copy while it is "
        "in the foreground, with no reliable warning to you",
    )


def main(argv):
    if len(argv) != 2:
        print("usage: python3 check_clipboard_access.py <device.json>")
        return 2
    with open(argv[1]) as f:
        device = json.load(f)

    label = device.get("device", "unknown device")
    api = device.get("api_level", 0)
    version = device.get("android_version", "?")
    print("Device: %s (Android %s, API %d)" % (label, version, api))
    print("Clipboard protection: %s" % toast_status(api))
    print()

    apps = device.get("apps", [])
    high = 0
    print("%-40s %-10s %-8s %s" % ("Package", "Kind", "Risk", "Notes"))
    for app in sorted(apps, key=lambda a: a.get("package", "")):
        risk, note = risk_for(app)
        if risk == "HIGH":
            high += 1
        print(
            "%-40s %-10s %-8s %s"
            % (
                app.get("package", "?"),
                app.get("kind", "?"),
                risk,
                note,
            )
        )

    print()
    if high:
        print("Result: %d high risk app(s) can read the clipboard." % high)
        print("To block one, run:")
        for app in apps:
            risk, _ = risk_for(app)
            if risk == "HIGH":
                print(
                    "  adb shell cmd appops set %s READ_CLIPBOARD ignore"
                    % app.get("package")
                )
        print("Revoke access only for apps you do not need pasting from.")
        print("A keyboard you rely on will stop pasting if you block it.")
        return 1
    print("Result: no high risk app found.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
