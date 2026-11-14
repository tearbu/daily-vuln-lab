# Android clipboard toast bypass lab

A checker that audits which apps on an Android device can read the clipboard, built around Toni Noble's 2026-11-13 disclosure that an app can hide Android's clipboard read toast by firing its own toasts first. Full write-up in `analysis.md`.

## Running it

```bash
python3 check_clipboard_access.py sample_device.json
python3 check_clipboard_access.py sample_device_old.json
```

The sample files are fictional. For a real audit, build the JSON from your own device with `adb shell cmd appops query-op --user 0 READ_CLIPBOARD allow` and your Android version.

## Captured output

Fictional Android 14 phone (exit code 1, three high risk apps):

```
Device: Pixel 8 (fictional sample) (Android 14, API 34)
Clipboard protection: toast shown on clipboard read (Android 12 and later), but a malicious app can hide that toast, see analysis.md

Package                                  Kind       Risk     Notes
com.android.systemui                     system     MEDIUM   a system app with clipboard access, expected on most devices
com.example.bank                         third-party HIGH     a third party app that can read anything you copy while it is in the foreground, with no reliable warning to you
com.example.game                         third-party UNKNOWN  mode is the system default, confirm it on the device with `adb shell cmd appops get <package> READ_CLIPBOARD`
com.example.messenger                    third-party HIGH     a third party app that can read anything you copy while it is in the foreground, with no reliable warning to you
com.example.notes                        third-party OK       clipboard read is blocked for this app
com.example.social                       third-party HIGH     a third party app that can read anything you copy while it is in the foreground, with no reliable warning to you
com.google.android.inputmethod.latin     keyboard   MEDIUM   a keyboard needs clipboard access to paste, but it can also read anything you copy, so it is worth trusting

Result: 3 high risk app(s) can read the clipboard.
To block one, run:
  adb shell cmd appops set com.example.social READ_CLIPBOARD ignore
  adb shell cmd appops set com.example.bank READ_CLIPBOARD ignore
  adb shell cmd appops set com.example.messenger READ_CLIPBOARD ignore
Revoke access only for apps you do not need pasting from.
A keyboard you rely on will stop pasting if you block it.
```

Fictional Android 9 handset (exit code 1, no toast protection at all):

```
Device: Old handset (fictional sample) (Android 9, API 28)
Clipboard protection: no toast, and background apps can read the clipboard (before Android 10)

Package                                  Kind       Risk     Notes
com.example.flashlight                   third-party HIGH     a third party app that can read anything you copy while it is in the foreground, with no reliable warning to you
com.example.social                       third-party HIGH     a third party app that can read anything you copy while it is in the foreground, with no reliable warning to you

Result: 2 high risk app(s) can read the clipboard.
To block one, run:
  adb shell cmd appops set com.example.social READ_CLIPBOARD ignore
  adb shell cmd appops set com.example.flashlight READ_CLIPBOARD ignore
Revoke access only for apps you do not need pasting from.
A keyboard you rely on will stop pasting if you block it.
```
