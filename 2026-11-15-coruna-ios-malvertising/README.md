# Coruna iOS malvertising, 15 November 2026

Dutch news sites Bright.nl, VI.nl, Autoblog and GeenStijl spread
malicious code through their ads in early November 2026. The ad
system of an outside supplier had been hacked, and the attackers
planted code in an ad tag. The tag harvested visitor data and tried
to exploit older iPhones with the Coruna iOS exploit kit. The full
write-up is in [analysis.md](analysis.md).

## The lab

`coruna_exposure_check.py` is a Python standard library script with
two checks:

- `devices`: reads a CSV inventory of iPhones and iPads and flags
  every device below the fixed iOS version for its branch.
- `log`: scans a web access log and flags ad tag requests that ship
  device fingerprint details (screen size, language, OS, referrer)
  to a third party host, the pattern the incident report describes.

Sample data is fictional. No exploit code is included.

## Running it

```
python3 coruna_exposure_check.py devices sample_inventory.csv
python3 coruna_exposure_check.py log sample_ad_traffic.log
```

## Captured output

Device check, run 15 November 2026:

```
Device exposure check: sample_inventory.csv
----------------------------------------------------------------
[VULNERABLE] iPhone 6s (spare) (iOS 15.8.5): below 15.8.7; exposed to CVE-2023-41974, CVE-2024-23222, CVE-2023-43000, CVE-2023-43010
[OK] iPhone 7 (test bench) (iOS 15.8.7): at or above 15.8.7
[VULNERABLE] iPhone 8 (reception) (iOS 16.7.14): below 16.7.15; exposed to CVE-2023-43010
[OK] iPhone X (field kit) (iOS 16.7.15): at or above 16.7.15
[VULNERABLE] iPhone 12 (staff) (iOS 17.2): below 17.3; exposed to CVE-2024-23222, CVE-2023-43010
[OK] iPhone 13 (staff) (iOS 17.3): at or above 17.3
[VULNERABLE] iPhone 15 (staff) (iOS 18.7.2): below 18.7.3; exposed to CVE-2025-43529
[OK] iPhone 16 (staff) (iOS 18.7.3): at or above 18.7.3
[OK] iPhone 17 (staff) (iOS 26.3): at or above 26.3
[OK] iPad Air 2 (lobby) (iOS 15.8.7): at or above 15.8.7
[UNKNOWN] iPhone 6 (museum piece) (iOS 12.5.7): no Coruna version rule recorded for iOS 12
----------------------------------------------------------------
Summary: 4 vulnerable, 6 ok, 1 unknown
```

Log scan, run 15 November 2026:

```
Ad traffic log scan: sample_ad_traffic.log
----------------------------------------------------------------
[FLAG] 192.0.2.10 - - [14/Nov/2026:09:12:02 +0100] "GET https://adtag.example-ads.test/serve?slot=leaderboard&screen=390x844&lang=nl-NL&os=iOS%2018.7.2&ref=https%3A%2F%2Fexample-news.test%2Fnews%2Farticle-4821 HTTP/1.1" 200 918 ...
       ad host adtag.example-ads.test sent fingerprint fields: lang, os, ref, screen
[FLAG] 192.0.2.44 - - [14/Nov/2026:09:15:41 +0100] "GET https://adserver.example-ads.test/tag?id=8841&sw=390&sh=844&lang=nl-NL&os=iOS%2016.7.14&ua=iPhone&tz=Europe%2FAmsterdam HTTP/1.1" 200 1204 ...
       ad host adserver.example-ads.test sent fingerprint fields: lang, os, sh, sw, tz, ua
----------------------------------------------------------------
Summary: 2 of 8 requests flagged as ad tag fingerprinting
```

The log lines above are trimmed for readability. The full lines are in
`sample_ad_traffic.log`.
