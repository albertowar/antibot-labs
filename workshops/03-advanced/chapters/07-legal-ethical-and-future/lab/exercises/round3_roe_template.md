# Rules of Engagement: Workshop 3 Capstone (team draft)

> Fill in every section. Tomorrow's red-team phase runs under this document, and the other team will try to find the gap in it. Score a draft with `python tools/checkpoint.py 3 --roe <this file>`.

**Team:** _______________ **Opponent team:** _______________ **Date:** _______________

## 1. Authorisation

Who authorises this engagement, in writing: _______________ (name and role). They can revoke it at any time by: _______________. Each member of both teams has read and signed this document (section 12).

## 2. In-scope targets

| Target | Host / port | Owner | Notes |
|---|---|---|---|
| Our store stack | `127.0.0.1:____` | us | |
| Opponent's store stack | `________:____` | opponent | assigned by the instructor |
| | | | |

All attack traffic originates from the lab network and uses only the documentation address ranges in `data/world.json` where source addresses are simulated. Nothing leaves the lab network.

## 3. Out of scope

Not targets, under any circumstances: other teams' stacks, the instructor's machines and network, the venue's infrastructure, any internet host, any third-party service (including the vendor endpoints a CAPTCHA or fingerprinting library might call).

## 4. Prohibited techniques

- Denial of service, volumetric floods or resource exhaustion beyond the limits in section 5.
- Direct access to the opponent's Redis, PostgreSQL or filesystem. Attacks go through the HTTP surface the opponent chose to expose.
- Exploitation of the host, the container runtime or Flask debug endpoints.
- Credential reuse: no password found here is tried anywhere else, ever.
- Anything that persists after the exercise ends (planted accounts, scheduled jobs, modified data the opponent did not agree to).

## 5. Traffic limits

Maximum ______ requests per second per attacker, sustained for at most ______ minutes per run. Windows: ______ to ______. The defender may ask for a pause of up to ______ minutes to redeploy.

## 6. Synthetic data only

All accounts, credentials, emails, names, addresses and payment details are synthetic and come from the lab's generators. No team member's real identity, email or device is used in any flow, including step-up challenges.

## 7. Data handling

Captured traffic, decision logs and screenshots of the opponent's system: kept until ______ , then deleted. They are not copied off the lab machines and not used after the workshop (including to train models) without the opponent's written agreement.

## 8. Deception limits

Honeypots and decoy endpoints: allowed. Tarpits: allowed up to ______ seconds per response. Poisoned data: allowed only if it stays inside the opponent's lab stack and is declared at the debrief. No deception that targets a person rather than a program.

## 9. Stop conditions

Anyone on either team or the instructor can call **STOP** by _______________ (channel). All attack traffic halts within 60 seconds. Resume only when the person who called it says so. Automatic stop if: the opponent's stack is unreachable for more than ______ seconds; any traffic reaches an out-of-scope host; anyone suspects real personal data is involved.

## 10. Disclosure

Each team gives the opponent a written findings report by ______ (time) using `exercises/disclosure_template.md`. Bypasses are shown to the opponent before the plenary. No public write-up names a person without their consent. Vulnerabilities in the shared workshop code go to the instructor first.

## 11. False-positive accountability

The defender publishes, per round, the blocked and challenged rates for every legitimate cohort in the traffic simulator (`tools/fp_audit.py` format). Blocked legitimate users count against the defending team's score at ______ points per percentage point over the 2% budget. Hiding the number is a scoring breach.

## 12. Referee, disputes and signatures

The referee is _______________. Scope questions are asked before acting, not after. A contested block or a contested finding is appealed to the referee, whose decision is final for the day.

| Name | Team | Signature | Time |
|---|---|---|---|
| | | | |
| | | | |
| | | | |
| | | | |
