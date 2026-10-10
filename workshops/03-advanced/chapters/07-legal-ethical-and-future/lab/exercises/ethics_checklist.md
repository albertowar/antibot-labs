# Pre-Deployment Checklist (defender and red team)

Use this before deploying a detection technique in production, or before running an attack technique in an authorised engagement. It is the checklist behind the Round 2 exposure notes and the Round 3 rules of engagement. Adapted from the series' earlier ethics checklist and refreshed for October 2026.

## Authorisation

- [ ] I have **explicit, written permission** to test or interact with this system, from someone who can give it.
- [ ] The scope of that permission covers the specific technique, the specific targets and the time window.
- [ ] I can produce the authorisation if asked, and I know who can revoke it.
- [ ] If I am doing good-faith security research without a contract, I have read the DOJ's 2022 CFAA charging policy (US) and know that the UK's statutory researcher defence was still pending legislation as of October 2026. Neither is a licence to test systems I was not invited to test.

## Harm assessment

- [ ] I know who could be harmed: users, third parties sharing the infrastructure, the target organisation.
- [ ] I have considered side effects (will my load affect unrelated users on the same host, CDN or carrier NAT?).
- [ ] I can stop and revert within a minute if something goes wrong, and I know who to tell.

## Proportionality (the detection side)

Match the invasiveness of detection to the risk of the resource it protects.

| Risk | Example | Signals that fit | Signals that do not |
|---|---|---|---|
| Low | Public catalogue, blog | Rate limits, header checks, proof-of-work | Behavioural biometrics, device attestation |
| Medium | Checkout, account creation | IP reputation as points, fingerprint consistency, self-hosted challenge | Hard blocks on Tor or VPN |
| High | Payments, account recovery | Step-up authentication, device binding, attestation on native apps | Silent blocks with no appeal path |

- [ ] No hard rule on *where* someone connects from (Tor, VPN, datacenter, country) unless the risk justifies refusing that whole population and someone has signed off on that.
- [ ] Protected cohorts (assistive technology, privacy browsers, shared NAT, old devices) are capped at a **challenge**, never silently blocked, and the challenge has an accessible alternative.

## Data minimisation and lawful basis (EU and UK, and good practice elsewhere)

- [ ] The lawful basis for the security processing is written down (usually legitimate interest, GDPR Art 6(1)(f), Recitals 47 and 49) and the balancing test exists on paper.
- [ ] Anything stored on or read from the user's device for detection is either **strictly necessary** for the service the user asked for or covered by consent (ePrivacy Art 5(3); EDPB Guidelines 2/2023, v2.0, October 2024). "Fraud prevention" stretches "strictly necessary" only so far; the fingerprint must be for security, not reused for marketing.
- [ ] Third-party challenge or fingerprinting vendors: I know what they receive, where it goes, and on what transfer basis. There is a consent story or a self-hosted alternative.
- [ ] Decision logs have a retention period measured in weeks, with a written reason if longer, and a deletion job that actually runs.
- [ ] Behavioural biometrics (keystroke, mouse dynamics) are not repurposed as persistent identifiers. If they are used to identify a person, Illinois BIPA and Texas CUBI apply to those residents, and GDPR Art 9 may.

## Transparency and appeal

- [ ] The privacy notice says that security signals are collected and what for.
- [ ] A blocked person can reach a human (GDPR Art 22 for decisions with significant effects; plain customer service for everything else).
- [ ] My organisation knows what I deployed and why; the false-positive rate per cohort is on a dashboard someone looks at.

## Accessibility

- [ ] Every challenge has a non-visual, keyboard-operable path (WCAG 2.2 SC 1.1.1, 2.1.1, 3.3.8). The European Accessibility Act has applied to consumer-facing e-commerce since 28 June 2025; US ADA litigation over websites continues regardless of the Title II rule's dates.
- [ ] Keyboard-only and screen-reader users were in the legitimate-traffic simulator when the policy was tuned.

## The dual newspaper test

- [ ] My actions would **not** be reported as a harmful or malicious attack.
- [ ] My actions would **not** be reported as invasive, disproportionate surveillance.

## When to say no

Requests that should raise an immediate flag:

- "Add tracking to a third-party site without their knowledge."
- "Scrape personal data from social media to profile our own users."
- "Test our resilience against our competitor's infrastructure."
- "Seed the platform with bot accounts for engagement."
- "Reuse the keystroke data to recognise users across sessions without cookies."
- "Block the whole country; it's cheaper than the fraud."

A business justification does not make an activity legal, and legal does not make it proportionate. Know your lines before you are asked, and have the words ready for declining without drama.
