# Android clipboard read toast can be hidden by an app's own toasts

Picked from Hacker News on 2026-11-14. The story, "Ctrl+C, Ctrl+v, Ctrl+cve: Bypassing Android's Clipboard Read Security Measures" by Toni Noble, was posted on 2026-11-13 and had 93 points and 47 comments when I checked. It was the clear pick of the day: a concrete bypass with a write-up and a demo, a huge affected population, and a direct defensive angle. There was no new named CVE with a CVSS score in the window, and the other candidates were an incident update from Cursor and a research piece on WordPress plugin fixes, neither of which had a single vulnerability to build a lab around.

## What it is

Android added a small warning to protect the clipboard. Since Android 12, every time an app reads clipboard data that another app copied, the system shows a toast saying the app pasted from your clipboard. The idea is that you notice the read happening.

Toni Noble found that an app can hide that warning. Her test app fired two of its own toasts in quick succession around the clipboard read, and the app's toasts took precedence over the system toast. The user saw the app's messages instead of the warning, and had no idea the clipboard had been read. She published a screen recording of the test app doing this.

The clipboard matters because of what people copy into it. Passwords, MFA codes, private messages, and account details all pass through it. Her opening example is a support team superuser password shared in Slack, copied, pasted into a VPN client, and then deleted from Slack. Deleting the message does not clear the clipboard. Any app that can read it still gets the secret.

## Affected products

Any device running Android 12 or later (API level 31 and up) is in scope for this bypass, because that is where the toast exists. The article names no specific device, manufacturer build, or patch level, and does not claim a narrower range. Older devices are worse off in a different way. Before Android 10, background apps could read the clipboard at all, and Android 10 and 11 block background reads but show no toast, so a foreground read on those versions is silent too.

## Severity

The Android Security Team rated this Moderate severity. There is no CVE ID in the article text, and no CVSS score, so there is no number to quote. Google's reply, shown as a screenshot in the article and dated 2026-11-12, says the status is "Won't Fix (Infeasible)" and that the report will be passed to the feature team for remediation in a potential upcoming release. In plain terms, there is no patch to install. The author held publication from the end of July 2026 until she got that answer, then disclosed it publicly on 2026-11-13.

## Exploitation status

This is a disclosed bypass, not an observed attack. The article reports no exploitation in the wild and no malicious app caught doing this. What it does show is that the technique is simple: a test app built for the purpose, two toasts, and the warning is gone. No exploit code is published in the article, and none is included here.

## How it works, as far as the public sources go

The mechanism is a user interface race, not a memory bug. Android shows its clipboard read toast, but an app can display its own toasts at the same moment, and the app's toasts win the screen. The read itself is legitimate from the system's point of view: a foreground app is allowed to read the clipboard, and the toast is the only thing standing between that read and the user's awareness. Remove the toast and the read is invisible.

Two points from the article are worth keeping in mind. First, Google's own documentation on secure clipboard handling puts the job of protecting copied content on app developers, and says other app developers may act as potential threat actors. Second, Android does offer a flag, `ClipDescription.EXTRA_IS_SENSITIVE`, that lets an app mark copied content as sensitive so the keyboard preview is visually hidden. Google Authenticator uses it for MFA codes. That flag hides the preview. It does not stop an app from reading the clipboard.

## Detection ideas

The author gives no formal detection guidance, so what follows is my own reasoning from the facts in the article, not something she published.

1. Audit which apps can read the clipboard. The checker script in this folder does this against a device description, and the `adb` commands it prints work on a real device: `adb shell cmd appops query-op --user 0 READ_CLIPBOARD allow` lists the apps with access, and `adb shell cmd appops set <package> READ_CLIPBOARD ignore` blocks one. The sample files are fictional, so run it against your own device for a real result.
2. Look for apps that have no business pasting. A flashlight, a wallpaper app, or a game that can read the clipboard is worth a second look. Keyboards and password managers need the access, so the question is whether you trust the app, not whether it has the permission at all.
3. Treat the toast as unreliable. If you copy a password or a code, assume any foreground app could have read it, and clear the clipboard after pasting. Android clears clipboard items after a while on some builds, but do not rely on that.
4. For developers: mark sensitive copied content with the `EXTRA_IS_SENSITIVE` flag, and avoid putting secrets on the clipboard in the first place where a safer handoff exists, such as autofill.

## Mitigation and patch guidance

There is no patch, and no fixed version to upgrade to, because Google marked this Won't Fix. That leaves user side and developer side steps only.

For users: check which apps hold clipboard read access and revoke it from apps that do not need it, using the `adb` command above or your device's app ops settings if it exposes them. GrapheneOS has shipped a feature called Secure Paste that takes clipboard read access away from apps and gives users a dedicated paste action instead, and that is the closest thing to a fix available anywhere right now. Avoid copying passwords and codes where you can, and use a password manager's autofill instead of copy and paste.

For developers: use the `EXTRA_IS_SENSITIVE` flag for sensitive copied content. The author also filed a feature request asking Google for per-app clipboard permissions, like the ones that exist for location and notifications, and asks readers who agree to support it. That is a request, not a shipped control.

## The lab in this folder

`check_clipboard_access.py` is a Python standard library checker. Give it a JSON file describing a device (Android version, API level, and the apps with their clipboard read mode) and it reports each app as OK, MEDIUM, HIGH, or UNKNOWN, prints the `adb` commands to block the high risk ones, and exits 1 if any high risk app is found. `sample_device.json` is a fictional Android 14 phone with three third party apps that can read the clipboard, and `sample_device_old.json` is a fictional Android 9 handset with no toast protection at all. The output of both runs is in the folder README.

## Sources

- Toni Noble, "Ctrl+C, Ctrl+v, Ctrl+cve: Bypassing Android's Clipboard Read Security Measures", published 2026-11-13: https://toninoble.com/post/ctrlc-ctrlv-ctrlcve
- Hacker News thread, posted 2026-11-13: https://news.ycombinator.com/item?id=50487605
- Privacy Guides community discussion of the same disclosure, 2026-11-14: https://discuss.privacyguides.net/t/ctrl-c-ctrl-v-ctrl-cve-the-android-clipboard-risk-google-wont-fix/42210
- Android Authority, "GrapheneOS just fixed one of Android's sneakiest privacy problems" (Secure Paste): https://www.androidauthority.com/grapheneos-secure-paste-merged-3710734/

## What I could not verify

No CVE ID appears in the article text or in the screenshot of Google's reply, so I cannot link an NVD entry or quote a CVSS score. The screenshot shows the sender's address redacted and the issue number as #12, which is not enough to find the tracker entry. The article names no specific device or build, so I cannot say whether any manufacturer has changed this behavior on its own. The detection steps above are my own suggestions, not guidance from the author.
