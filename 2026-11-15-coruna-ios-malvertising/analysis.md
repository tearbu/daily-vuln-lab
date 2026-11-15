# Coruna iOS exploit kit delivered through hacked ads on Dutch news sites

## What happened

On 15 November 2026, Dutch tech site Bright.nl and football news site
VI.nl warned readers that they had unknowingly spread malicious code
through advertisements in early November. Autoblog and GeenStijl were
named as affected too, and more sites may have been hit. The attack
came through the advertising system of an external software supplier.
GeenStijl named the advertising service provider as Next Day Media.

Attackers had unauthorised access to that ad system between 1 and
3 November, and again on 11 November. In early November they added
malicious code to an advertising tag. Every visitor who loaded the tag
had data sent to an attacker controlled server: IP address, pages
visited, referring pages, screen size, language settings, and
operating system details. The code was also built to attack iPhones.
It tried to exploit vulnerabilities in older iOS versions, iOS 18.7.2
and older, and iOS versions before 15.8.7 and 16.7.15.

The sites say the malicious code has been removed and the flaw in the
ad system has been fixed. The investigation was still open when the
article was published. It was confirmed that visitor data reached the
attackers. It was not established whether any iPhone was actually
taken over. The sites said they could not tell, for each individual
visitor, whether the code had loaded or what data had been sent.
Visitors were advised to install the updates, change their passwords,
and move any cryptocurrency to a new wallet with a new recovery
phrase.

## The kit: Coruna

GeenStijl identified the malicious code as the iOS exploit kit
Coruna. Google Threat Intelligence Group has described Coruna as an
exploit kit with five exploit chains and 23 individual exploits,
reported to target devices running about iOS 13.0 through iOS 17.2.1.
Apple tied its March 2026 backports for older devices to Coruna, and
CISA added two of the kit's CVEs to its Known Exploited
Vulnerabilities catalog on 5 March 2026.

Coruna is a kit, not a single flaw. The CVEs below are the ones Apple
named in the backports that close off its paths on devices that
cannot run the newest iOS.

## The vulnerabilities

| CVE | Component | Impact | CVSS 3.1 | KEV |
| --- | --- | --- | --- | --- |
| CVE-2024-23222 | WebKit, type confusion | Crafted web content can lead to arbitrary code execution | 8.8 High | Added 23 Jan 2024 |
| CVE-2023-43000 | WebKit, use-after-free | Crafted web content can lead to memory corruption | 8.8 High | Added 5 Mar 2026 |
| CVE-2023-43010 | WebKit, memory handling | Crafted web content can lead to memory corruption | 8.8 High | Not listed |
| CVE-2023-41974 | Kernel, use-after-free | An app may execute arbitrary code with kernel privileges | 7.8 High | Added 5 Mar 2026 |
| CVE-2025-43529 | WebKit, use-after-free | Crafted web content can lead to arbitrary code execution | 8.8 High | Added 15 Dec 2025 |

CVSS scores are the values published in the CVE.org records for
these CVEs. The NVD API returned a 503 error from this environment
on 15 November 2026, so the scores were taken from the CVE.org API
records instead, and the KEV dates from the CISA KEV feed checked the
same day.

CVE-2025-43529 is not one of the March 2026 backport CVEs. It is in
the table because it is the WebKit flaw in the related chain that
targets the iOS 18 line: Apple fixed it in iOS 18.7.3 and iOS 26.2,
and Apple said it was aware of a report that it may have been
exploited in an extremely sophisticated attack against specific
targeted individuals running iOS versions before iOS 26. That is the
flaw behind the Tweakers article's mention of iOS 18.7.2 and older.

## Fixed versions

Apple's March 11, 2026 backports, for devices that cannot move to a
newer iOS:

- iOS 15.8.7 and iPadOS 15.8.7: fixes CVE-2023-41974, CVE-2024-23222,
  CVE-2023-43000, CVE-2023-43010. For iPhone 6s, iPhone 7, iPhone SE
  (1st generation), iPad Air 2, iPad mini 4, iPod touch 7th
  generation.
- iOS 16.7.15 and iPadOS 16.7.15: fixes CVE-2023-43010. For iPhone 8,
  iPhone 8 Plus, iPhone X, iPad 5th generation, iPad Pro 9.7 inch and
  12.9 inch 1st generation.
- On the current lines, CVE-2024-23222 was fixed in iOS 17.3 and
  CVE-2025-43529 in iOS 18.7.3 and iOS 26.2.

## How it works, at the level the sources support

This was a watering hole attack delivered through advertising. A
visitor did not need to click anything. Loading a page on an affected
site loaded the compromised ad tag, and the tag ran in the visitor's
browser. The tag first harvested device details and sent them to the
attacker server. On a phone running a vulnerable iOS version, the kit
could then try the exploit chain for that version. That is the shape
of the attack the public sources describe.

What the sources do not say: the exact chain the attackers used in
this incident, which of the 23 Coruna exploits were served, whether
any visitor's phone was actually compromised, and what the attackers
changed in the ad system on 11 November. Those points were
unconfirmed when the Tweakers article was published, and this lab
does not guess at them.

## Detection ideas

The lab script in this folder covers two checks a defender can run
with data they already have.

1. Inventory check. Pull the iOS version of every phone and tablet
   in the fleet and compare it with the fixed versions above. Anything
   below the fixed version for its branch is exposed to the kit. The
   script flags those devices and names the CVEs.
2. Ad tag traffic check. Look at web proxy or access logs for ad tag
   requests that carry fingerprint details to a third party host:
   screen size, language, operating system, referrer. A normal ad
   creative request is a plain image or script fetch. A request that
   ships the visitor's screen size, language, and OS version in the
   query string is worth a closer look. The script flags requests
   from ad-like hosts that carry two or more of those fields.

Other signals worth watching: a sudden change in the ad tags served
on your own site, new third party domains appearing in page loads,
and outbound requests from browsers to hosts that do not belong to
your ad partners.

## Mitigation

- Update every iPhone and iPad to iOS 15.8.7, 16.7.15, 17.3 or
  later, 18.7.3 or later, or 26.2 or later, whichever fits the
  device. Devices stuck below iOS 15 have no published Coruna
  backport. Treat them as exposed and keep them off sensitive work.
- Site owners: audit every third party script and ad tag on your
  pages. A compromised ad supplier reaches all your visitors at
  once. Pin down which ad hosts are allowed, watch for changes in
  the tags, and use Content Security Policy to limit where scripts
  can load from.
- Visitors to the affected sites were told to change passwords and
  move cryptocurrency funds. That advice fits any incident where
  session or credential data may have been harvested, and it is cheap
  to follow.

## Sources

- Hacker News, "Dutch news websites were spreading iPhone-malware
  via ads", item 50506066, 15 November 2026.
  https://news.ycombinator.com/item?id=50506066
- Tweakers, "Bright.nl, VI.nl en andere websites verspreidden
  iPhone-malware via advertenties", Jasper Bakker, 15 November 2026.
  https://tweakers.net/nieuws/254546/bright-punt-nl-vi-punt-nl-en-andere-websites-verspreidden-iphone-malware-via-advertenties.html
- Apple, "About the security content of iOS 15.8.7 and iPadOS
  15.8.7", released 11 March 2026.
  https://support.apple.com/en-us/126632
- Apple, "About the security content of iOS 16.7.15 and iPadOS
  16.7.15", released 11 March 2026.
  https://support.apple.com/en-us/126646
- CVE.org records for CVE-2024-23222, CVE-2023-43000,
  CVE-2023-43010, CVE-2023-41974, checked 15 November 2026.
  https://cveawg.mitre.org/api/cve/CVE-2024-23222
- CISA Known Exploited Vulnerabilities catalog, checked
  15 November 2026.
  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
- Ostorlab, "APT29 Watering Holes Exploit Mobile n-Days
  (CVE-2024-27834)", 4 November 2026, for the iOS 18 chain and the
  CVE-2025-43529 fix version.
  https://blog.ostorlab.co/apt29-plerdy-watering-hole-supply-chain.html
