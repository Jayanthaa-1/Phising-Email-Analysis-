# Phising-Email-Analysis

 Email Header Forensics

![Status](https://img.shields.io/badge/Status-Completed-brightgreen?style=flat-square)
![Level](https://img.shields.io/badge/Level-SOC%20L1-blue?style=flat-square)
![Severity](https://img.shields.io/badge/Severity-High-red?style=flat-square)
![Verdict](https://img.shields.io/badge/Verdict-True%20Positive-red?style=flat-square)
![Compromised](https://img.shields.io/badge/Credentials%20Compromised-None-brightgreen?style=flat-square)

---

## What I Did

Investigated a reported phishing email targeting a user via a spoofed Microsoft 365 security alert. Performed full email header analysis, validated SPF/DKIM/DMARC authentication results, traced relay hops, extracted IOCs, and validated each one using VirusTotal, URLScan.io, and AbuseIPDB. Completed containment and documented all findings.

---

## Environment

- **Tools:** MXToolbox Header Analyser, VirusTotal, URLScan.io, AbuseIPDB
- **Source:** User-reported suspicious email (forwarded to SOC with full headers)
- **Lure:** Spoofed Microsoft 365 account suspension alert

---

## Evidence

### 1 — The Phishing Email (Sanitised)

```
From     : no-reply@microsoft-account-alert.net
To       : [redacted]@[redacted].co.uk
Subject  : URGENT: Your Microsoft 365 account has been suspended
Date     : 19 Nov 2024  09:43 UTC
────────────────────────────────────────────────────────────────

Dear Microsoft 365 User,

We have detected multiple failed sign-in attempts on your account.
Your account has been temporarily suspended for your protection.

You must verify your identity in the next 2 hours or your account
will be permanently deleted.

Click here to verify:
hxxps://ms365-verify.account-unlock[.]co/auth

Microsoft Support Team

────────────────────────────────────────────────────────────────
IMMEDIATE RED FLAGS:
  [!] microsoft-account-alert.net — NOT a Microsoft domain
  [!] "2 hours or permanently deleted" — fake urgency
  [!] account-unlock[.]co — NOT a Microsoft domain
  [!] Microsoft never suspends accounts via email links
  [!] User confirmed their account was working fine
```

### 2 — Full Email Header (Key Fields Extracted)

```
Received: from mail.bulk-send[.]online (194.165.16.72)
          by mx1.[redacted].co.uk
          at 19 Nov 2024 09:43:58 +0000

Received: from [194.165.16.72]
          by mail.bulk-send[.]online
          at 19 Nov 2024 09:43:11 +0000

From         : "Microsoft Support Team" <no-reply@microsoft-account-alert.net>
Reply-To     : support@helpdesk-ms365[.]ru
Return-Path  : <bounce@bulk-send[.]online>
X-Originating-IP: 194.165.16.72
Message-ID   : <20241119094311.11423@bulk-send[.]online>

Authentication-Results: mx1.[redacted].co.uk;
  spf=fail    smtp.mailfrom=microsoft-account-alert.net
  dkim=none   (no signature)
  dmarc=fail  (p=none — not enforced)
```

### 3 — SPF / DKIM / DMARC Results (via MXToolbox)

```
┌──────────────────────────────────────────────────────────────────┐
│  MXToolbox Header Analyser — Authentication Results              │
├────────┬──────────┬────────────────────────────────────────────┤
│ Check  │ Result   │ Analysis                                   │
├────────┼──────────┼────────────────────────────────────────────┤
│ SPF    │ FAIL     │ IP 194.165.16.72 not in domain SPF record  │
│        │          │ Not authorised to send from this domain    │
├────────┼──────────┼────────────────────────────────────────────┤
│ DKIM   │ NONE     │ No signature present at all                │
│        │          │ Legitimate Microsoft emails are always     │
│        │          │ DKIM signed — absence confirms spoofing    │
├────────┼──────────┼────────────────────────────────────────────┤
│ DMARC  │ FAIL     │ Both SPF and DKIM failed                   │
│        │          │ Policy p=none — email not rejected         │
│        │          │ Should be p=reject to block at gateway     │
└────────┴──────────┴────────────────────────────────────────────┘

ALL THREE CHECKS FAILED — CONFIRMED SPOOFED EMAIL
```

### 4 — Relay Hop Analysis

```
Relay chain reconstructed from Received headers:

[ORIGIN]
  194.165.16.72
  (unknown IP — not in any Microsoft range)
       |
       v
[HOP 1]
  mail.bulk-send[.]online
  Unknown bulk mail relay — no association with Microsoft
  Timestamp: 09:43:11 UTC
       |
       v
[HOP 2]
  mx1.[redacted].co.uk  ← Our inbound mail gateway
  Timestamp: 09:43:58 UTC
  DMARC p=none — email passed through, not quarantined
       |
       v
[DELIVERED]
  Target user mailbox — 09:44 UTC

ANOMALIES:
  [!] Reply-To is helpdesk-ms365[.]ru — Russian domain
      (any replies go directly to attacker)
  [!] Message-ID domain (bulk-send.online) does not match From domain
  [!] Return-Path bounce address on bulk-send.online — not Microsoft
```

### 5 — IOC Extraction

```
Extracted from headers and email body:

IOC-01  194.165.16.72
        Type   : IP Address (X-Originating-IP)
        Source : Email header

IOC-02  microsoft-account-alert.net
        Type   : Domain (spoofed sender)
        Source : From / Reply-To header

IOC-03  account-unlock[.]co
        Type   : Domain (phishing page)
        Source : Embedded link in email body

IOC-04  hxxps://ms365-verify.account-unlock[.]co/auth
        Type   : URL (credential harvesting link)
        Source : Embedded link in email body

IOC-05  helpdesk-ms365[.]ru
        Type   : Domain (attacker reply-to)
        Source : Reply-To header
```

### 6 — AbuseIPDB — 194.165.16.72

```
┌────────────────────────────────────────────────────┐
│  AbuseIPDB — IP Report                             │
│                                                    │
│  IP Address         : 194.165.16.72                │
│  Abuse Confidence   : 94%                          │
│  Total Reports      : 312                          │
│  Distinct Reporters : 87 users                     │
│  Last Reported      : 19 November 2024 (today)     │
│                                                    │
│  Categories         : Phishing                     │
│                       Web Spam                     │
│                       Port Scan                    │
│                                                    │
│  Verdict            : MALICIOUS                    │
└────────────────────────────────────────────────────┘

This IP was actively reported for phishing on the same day
as this incident — confirms active live campaign.
```

### 7 — VirusTotal — microsoft-account-alert.net

```
┌────────────────────────────────────────────────────┐
│  VirusTotal — Domain Analysis                      │
│                                                    │
│  Domain          : microsoft-account-alert.net     │
│  Detection       : 21 / 90 vendors flagged         │
│  Categories      : Phishing, Malicious, Spam       │
│  Domain Age      : 5 days (registered 14 Nov 2024) │
│  Hosting         : DigitalOcean                    │
│                                                    │
│  Verdict         : MALICIOUS                       │
└────────────────────────────────────────────────────┘

VirusTotal — account-unlock[.]co

┌────────────────────────────────────────────────────┐
│  Domain          : account-unlock[.]co             │
│  Detection       : 19 / 90 vendors flagged         │
│  Categories      : Phishing                        │
│  Domain Age      : 5 days (registered 14 Nov 2024) │
│  Note            : Same registration date as above │
│                    — same attacker, same campaign  │
│                                                    │
│  Verdict         : MALICIOUS                       │
└────────────────────────────────────────────────────┘
```

### 8 — URLScan.io — Phishing Page Detonation

```
┌────────────────────────────────────────────────────────────────┐
│  URLScan.io — Safe Detonation Result                           │
│                                                                │
│  URL Submitted   : hxxps://ms365-verify.account-unlock[.]co/auth│
│  Final URL       : .../O365/auth/collect.php                   │
│  Page Title      : "Microsoft — Sign in to your account"       │
│  Hosting IP      : 94.102.49.88                                │
│  Hosting ASN     : Frantech Solutions (bulletproof hosting)    │
│  SSL Certificate : Let's Encrypt (padlock shown — false trust) │
│  Verdict         : MALICIOUS — Phishing                        │
│                                                                │
│  Page Behaviour:                                               │
│    - Renders convincing fake Microsoft 365 login page          │
│    - Form action: POST credentials to /O365/auth/collect.php   │
│    - No drive-by download detected                             │
│                                                                │
│  Note: SSL padlock does NOT mean a site is safe — attackers    │
│  use free Let's Encrypt certs to trick users                   │
└────────────────────────────────────────────────────────────────┘
```

### 9 — Full IOC Validation Summary

```
# IOC    TYPE        VALUE                              VERDICT
──────────────────────────────────────────────────────────────────
  01     IP          194.165.16.72                      MALICIOUS
                     AbuseIPDB: 94% confidence, 312 reports

  02     Domain      microsoft-account-alert.net        MALICIOUS
                     VirusTotal: 21/90, 5 days old

  03     Domain      account-unlock[.]co                MALICIOUS
                     VirusTotal: 19/90, same campaign

  04     URL         hxxps://ms365-verify.account-      MALICIOUS
                     unlock[.]co/auth                   Credential harvesting

  05     Domain      helpdesk-ms365[.]ru                MALICIOUS
                     VirusTotal: 11/90, attacker reply-to

All 5 IOCs confirmed malicious across VirusTotal, URLScan.io, AbuseIPDB
```

### 10 — Containment Actions Taken

```
ACTION 1 — Sender domain blocked at email gateway
  Rule added: block all inbound from microsoft-account-alert.net
  Result: Future emails from this domain will not reach users

ACTION 2 — Phishing domain sinkholed
  DNS sinkhole entry: account-unlock[.]co → 0.0.0.0
  Result: Even if a user clicks the link, DNS will not resolve

ACTION 3 — Email gateway searched for other recipients
  Search: subject LIKE "%account has been suspended%"
          AND sender LIKE "%microsoft-account-alert%"
  Result: No other recipients found — single target this wave

ACTION 4 — User confirmed no interaction
  Confirmed: link not clicked, credentials not entered
  Result: No compromise — account safe
```

### 11 — Incident Summary

```
┌─────────────────────────────────────────────────────────┐
│  INVESTIGATION SUMMARY                                  │
│                                                         │
│  Verdict              : TRUE POSITIVE — Phishing        │
│  Severity             : HIGH                            │
│  Credentials Stolen   : NO                              │
│  Domains Confirmed    : 4 malicious                     │
│  IPs Confirmed        : 1 malicious                     │
│  Containment Time     : 68 minutes from first report    │
│                                                         │
│  SPF  : FAIL   DKIM : NONE   DMARC : FAIL               │
│                                                         │
│  Biggest Gap Found : DMARC set to p=none (monitoring)   │
│  If p=reject was active, this email would have been     │
│  blocked automatically before reaching the user.        │
└─────────────────────────────────────────────────────────┘
```

---

## Key Findings

- All three email authentication checks (SPF, DKIM, DMARC) failed — technical confirmation of spoofing
- The sender domain was 5 days old at the time of attack — throwaway phishing infrastructure pattern
- The phishing page used a valid SSL certificate to show a padlock, creating false legitimacy
- The originating IP had 312 active abuse reports including reports on the same day — confirmed live campaign
- The most significant finding was DMARC set to monitoring mode (p=none) — enforcement would have automatically blocked this email

---

## Recommendations

- Change DMARC from `p=none` to `p=quarantine` then `p=reject`
- Deploy URL sandboxing on all inbound email links
- Enable MFA on all accounts — credential theft becomes ineffective
- Brief users: SSL padlocks do not mean a site is legitimate

---

## Skills Demonstrated

`Email Header Forensics` `SPF / DKIM / DMARC Analysis` `Phishing Detection` `IOC Extraction` `VirusTotal` `URLScan.io` `AbuseIPDB` `MXToolbox` `Threat Intelligence` `Containment Actions` `SOC L1 Workflow` `Investigation Reporting`

