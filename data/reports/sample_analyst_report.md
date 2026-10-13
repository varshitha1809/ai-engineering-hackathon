# PHISHDNA AI analyst report — A-261013-509643

- **Verdict:** Likely phishing (`LIKELY_PHISHING`)
- **Risk score:** 85.2 / 100 (policy risk score, not a probability)
- **Uncertainty:** low — none noted
- **Potential impact / priority:** high / P1
- **Data label:** user · **Source:** paste · **Analysed:** 2026-10-13T04:17:11.613098+00:00
- **Versions:** model `textclf-linear_svm-e1a96befb4`, rules `rules-1.0.0`, fusion `fusion-1.0.0`
- **Local state:** delivered (local record only — no mailbox action was taken)

## Message
- From: Northwind Supplies Billing <billing@northwind-supplies.example>
- Reply-To: northwind.accounts@outlook.com
- Subject: Change of bank details - please action today

## Decision
- risk 85.2 with 3 independent strong evidence groups (intent, identity, text_model)

## Attack reconstruction
The message claims to be: northwind supplies billing <billing@northwind-supplies.example>. 1 observed signal(s) were found, the strongest being: reply-to domain differs from from domain [F008]. It uses urgency, secrecy, financial diversion language. It asks the recipient to: change bank details. If malicious, a possible objective is payment diversion (bec) (inference, not established fact). Potential impact is rated high; verdict: Likely phishing.

_The system does not know the sender's real intent. Objectives are inferences from the linked evidence; no attacker attribution is made._

## Evidence
| ID | Status | Severity | Finding | Location | Observed | Method |
|---|---|---|---|---|---|---|
| F001 | observed | low | Social-engineering tactic: urgency | body[130:147] | …invoices must be paid to the new account below before end of day. Kindly keep this confidential while our… | rule rules-1.0.0 |
| F002 | observed | low | Social-engineering tactic: secrecy | body[156:178] | …account below before end of day. Kindly keep this confidential while our audit completes and do not call… | rule rules-1.0.0 |
| F003 | observed | low | Social-engineering tactic: financial diversion | subject[0:22] | Change of bank details - please action today | rule rules-1.0.0 |
| F004 | observed | low | Social-engineering tactic: financial diversion | body[270:284] | …office line.  Account number: [number …4416] Routing number: [number …0021]  Regards, Northwind Billing  | rule rules-1.0.0 |
| F005 | observed | high | Requested action: change bank details | subject[0:22] | Change of bank details - please action today | rule rules-1.0.0 |
| F006 | observed | info | Bank account reference in message | body | …4416 (masked) | rule rules-1.0.0 |
| F007 | inferred | high | Zero-link BEC pattern | body | actions: change_bank_details; tactics: secrecy, urgency | rule rules-1.0.0 |
| F008 | observed | high | Reply-To domain differs from From domain | header:Reply-To | From: billing@northwind-supplies.example \| Reply-To: northwind.accounts@outlook.com | rule rules-1.0.0 |
| F009 | unavailable | info | No Authentication-Results header | header:Authentication-Results | SPF/DKIM/DMARC: unavailable | rule rules-1.0.0 |
| F010 | observed | high | Trained text classifier score 0.95 | subject+body | score=0.954, threshold=0.521; top features: bank, our, account, kindly, not call | model textclf-linear_svm-e1a96befb4 |

## Recommended response
- Quarantine this message in the local case store and block its indicators locally.
- Show the recipient a warning banner (local recommendation).
- High potential impact: escalate to an analyst before anyone acts on the request.
- Confirm the sender through a contact channel you already know (directory, vendor master file) — not one given in this email. Confirmation would resolve the identity concern; the request itself should still follow normal approval.
- Before any payment or bank-detail change, call the requester on a previously known number and require a second approver.
- Check SPF/DKIM/DMARC as recorded by your own mail gateway; results inside an uploaded file are not verified.

## MITRE mapping
- T1566 — Phishing (no link/attachment sub-technique applies)

## Stage status
- mime: ok 
- html: not_applicable no HTML body
- parse: ok 0 URL(s), 0 attachment(s)
- social_engineering: ok 
- identity: ok 
- urls: ok 
- attachments: ok 
- ai_injection: ok 
- text_model: ok 
- threat_intel: ok 4 lookup(s); unknown means unknown
- correlation: ok 0 candidate relationship(s)

## Indicators
- sender_address: billing@northwind-supplies.example (reputation: unknown)
- sender_domain: northwind-supplies.example (reputation: unknown)
- reply_to_address: northwind.accounts@outlook.com (reputation: unknown)
- reply_to_domain: outlook.com (reputation: unknown)
- phone: …4416 (masked) (reputation: unknown)
- bank_account: …4416 (masked) (reputation: unknown)

## Case
- C-261013-509643: status open, priority P1, assignee —
