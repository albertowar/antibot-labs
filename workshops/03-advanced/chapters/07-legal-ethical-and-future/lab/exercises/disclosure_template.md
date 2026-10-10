# Findings Report Template (coordinated disclosure)

Use this for two things: the Capstone findings report each team owes its opponent (rules of engagement §10), and, outside the workshop, for reporting a vulnerability you found during authorised research or incidentally during defensive work. Replace every `[PLACEHOLDER]`.

Coordinated vulnerability disclosure is a norm, not a law. The 90-day window popularised by Google Project Zero is a convention vendors have come to expect; CERT/CC and national CSIRTs will coordinate when a vendor will not engage. Disclosure done this way is also what the DOJ's 2022 CFAA charging policy means by "good faith".

---

## Initial report (Day 0)

**To:** [security@vendor.example, the opposing team, or the programme URL]
**Subject:** [Severity] Finding: [one-line description]

### Summary

[One paragraph, plain language: what the issue is and what it allows. No exploit code here.]

### Severity

- **Estimated CVSS 4.0:** [e.g. 7.1, High]
- **Attack vector:** [Network / Adjacent / Local]
- **Privileges required:** [None / Low / High]
- **Impact:** [Confidentiality / Integrity / Availability, and which data or users]

### Technical details

- Affected component, endpoint or service: [ ]
- Steps to reproduce: [numbered]
- Observed versus expected behaviour: [ ]
- Sanitised request and response samples: [redact anything personal]

### Proof of concept

[Minimal reproduction, enough to confirm the issue, not a ready-to-run tool. For a critical finding, offer the PoC on request after acknowledgement instead of attaching it.]

### Who is affected, and who is exposed by the fix

[Which real users would be hurt if the fix is a blunter block. For a detection-bypass finding, say what cohort the bypass imitates (Tor, keyboard-only, carrier NAT), because the obvious patch will hit them.]

### Recommended remediation

[Optional. If the fix is a policy change, say which signal, weight or rule.]

### Disclosure timeline

- **Day 0:** this report.
- **Day 7:** follow-up if unacknowledged.
- **Day 90:** coordinated public disclosure if unresolved, timing agreed with you; no working exploit published. Earlier if the issue is being exploited in the wild; later if you show active remediation.

### Reporter

- Name or handle: [ ]
- Contact and PGP key: [ ]
- Programme reference, if any: [ ]

---

## Follow-up (Day 7, if unacknowledged)

**Subject:** Follow-up: [original subject]

I sent the report below on [DATE] and have not received an acknowledgement. Please confirm receipt and your expected review timeline. My disclosure timeline is unchanged.

---

## Before publishing anything

- [ ] At least 90 days (or the agreed window) since the first report, and at least one follow-up sent.
- [ ] Working exploit code removed or withheld.
- [ ] CVE requested through a CNA if the issue is in software others run.
- [ ] Any personal data encountered during the research has been deleted, and the write-up contains none.
- [ ] No private individual is named without consent.
- [ ] Counsel has reviewed if there is any doubt about authorisation or liability.
