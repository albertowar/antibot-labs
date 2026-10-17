# Walkthrough: the campaigns, the methods, the red herrings

Read after the reveal. One section per campaign: its signature in the log, which round's method finds it and why the earlier ones do not, and the legitimate cohort it hides behind. Account ids come from `answer_key.json`; use `timeline(df, account_id, around=first_compromise_event_id)` to look at any of them.

## Tier A — caught by rules

### A1 · Datacenter credential stuffing (14 victims)
**Signature.** Days 28–30: `login_failure` (`bad_password`) across ~900 accounts from a hosting block and six datacenter /24s, a browser User-Agent on a `python-requests` JA4, no fingerprint (`fp_hash` null: no JavaScript ran). For 14 accounts a `login_success` from the same space; minutes later the operator returns in a real browser from the same hosting range: `orders_viewed`, `payment_methods_viewed`, then for the persisted/monetised ones `password_change` → `email_change_confirmed` (to `fast.example`) → `notification_settings_changed` alerts off → `sessions_revoked_all`, `gift_card_purchased` or an order to a new US address. Four victims are **access-only**: login, read, leave.
**Found by.** Round 1, "stuffed then entered" (a datacenter failure then a datacenter password login) and "new context + high-risk change". The first rule is the only one that sees the access-only victims.
**Hides behind.** The 886 stuffing targets that were *not* taken over, the 600 sprayed once on day 44, and the 300 the store force-reset on day 31 (`actor=system`, `compromised_credential_policy`). Flag every account the wave touched and precision is 2%.

### A2 · Reset abuse: SIM swap and MFA fatigue (6 victims)
**Signature.** SMS users: `password_reset_requested` (`channel: sms`) from a mobile ASN in another country on a never-seen Android device, `mfa_challenge_success` (sms), `password_reset_completed`, login, `recovery_email_change`, `mfa_disabled` then `mfa_enabled` with a phone in the attacker's country, persistence, an order shipped there. Push users: 6–20 `mfa_challenge_failure` (`push_timeout` / `push_denied`) inside ten minutes, then a success and the same sequence.
**Found by.** Round 1, "MFA fatigue" and "reset from nowhere". One SMS victim has fewer than ten prior events in the log and slips the known-history clause: the price of the clause, and the reason time-to-detect is reported.
**Hides behind.** Forgetful owners (failures then a self-service reset from their own device) and legitimate support recoveries (ticket, reset, 40% from a new device). Also the real user who mistypes a TOTP three times.

### A3 · Impossible travel (6 victims)
**Signature.** The owner logs in at home; 20–50 minutes later a `login_success` from another continent on a new device, followed by `password_change`, `email_change_confirmed`, alerts off. Three of the six use the phishing kit's TLS stack and canvas fingerprint: the same operator runs both.
**Found by.** Round 1, "impossible travel" with two clauses: the second login is on a device the account has never used (this drops the geo-IP glitch, whose country jumps while IP and device stay the same) and a high-risk change follows within two hours. The sixth victim lives in the glitch block and is attacked on day 51, in the middle of the glitch; the device clause keeps it and drops the other 149.
**Hides behind.** Travellers (new country, known device; a quarter change their password on the trip), relocators, and the 150-account geo-IP glitch (days 50–52).

## Tier B — caught by the graph

### B1 · Phishing kit (20 victims, three operators)
**Signature.** Correct password first time, the victim's MFA relayed (`mfa_challenge_success` from the attacker), residential IPs in the victim's own country, `tz_offset` within an hour of the victim's, the victim's locale. Only medium-risk actions: `orders_viewed`, `payment_methods_viewed`, `address_added`, sometimes `payment_method_added`, `order_placed` to the new address at ~1.6× the victim's usual amount. One to three sessions over days 35–75. Identifiers rotate: `device_id` regenerated every 4–6 victims, `fp_hash` mutated one session in three, a fresh proxy IP per session. The JA4 is a real minority browser's (Chromium on Linux, ~1.5% of legitimate sessions).
**Found by.** Round 2: young, thin components on `device_id` + `fp_hash` (components of 2–8 accounts), plus seed expansion from the three A3 victims who share a fingerprint with operator 1. Round 3 adds three more whose only visit was a single session (new device, order to a new address, odd hour). Five are still unflagged after Round 3: one session each, a cookie and fingerprint no other victim's session shares. **Round 5** reaches all five: a session on a device the account first used at most 14 days earlier, an `address_added`, and an order to the new address. Two of the five spend their first session on a new cookie only reading the stored cards and order from the same cookie days later, so a rule that demands a brand-new device at the order session finds one or two; the 14-day window finds all five. Two of the five are thin accounts (fewer than ten earlier events in the log when they are attacked): the Round 1 history clause at 10 loses them again, at 5 they are back.
**Hides behind.** Linking on JA4 floods on the Chromium-Linux cohort; linking on IP floods on carrier NAT; a degree threshold at household level either misses the kit or flags the 110 households. Widening Round 1 to medium-risk events reaches a few victims and lands on new-phone upgraders and gift buyers.

### B2 · Session-cookie replay (10 victims)
**Signature.** A `login_success` with `auth_method: session_resume` and *no password event*, from a VPN exit or datacenter, on one buyer device (a legacy Chrome JA4) whose User-Agent is the stolen session's. Half reuse the stolen `session_id`; half are rotated children whose `details.parent_session_hash` points at it. Then `payment_methods_viewed`, an order to the exit's country, sometimes `passkey_added` or `api_token_created` with no password change at all.
**Found by.** Round 2: one `device_id` and `fp_hash` across the victims is a young, thin identifier with ten edges. Session stitching alone catches about half (the rotated ones) and is noisy: 8% of phone sessions legitimately move from wifi to cellular mid-session. The tenth victim is reached in Round 5: it orders to a new address on the buyer's device.
**Hides behind.** 55% of all logins are `session_resume`; roaming phones; always-on VPN users whose every session is from a datacenter ASN.

### B3 · OAuth link hijack (8 victims, four attacker identities)
**Signature.** A password login from a VPN or datacenter, then `third_party_linked` with a `provider_sub_hash` that two or three victims share; days later a `login_success` with `auth_method: oauth:<provider>` and that identity, then an order.
**Found by.** Round 2, after the same-person guard: the 80 duplicate-account owners also share one provider identity between two accounts, but they *also* share a desktop since the log began (old, thick edges). The attacker's pairs share only young, thin ones.
**Hides behind.** Duplicate-account owners: identical degree, different age.

### B4 · Support ring (8 victims, three agents)
**Signature.** `support_ticket_opened` (`channel: chat`, `lost_device`) from one browser profile on residential proxies in the victim's country; `support_reset_issued` by one of `agent-007`, `agent-019`, `agent-033`, `identity_check: passed`; `mfa_disabled` by the same agent if the victim had MFA; `password_reset_completed` and a login from the ring's device; `payment_methods_viewed`; a large order to a new address. The ring keeps the owner's email: the reset *is* the persistence.
**Found by.** Round 2: the eight tickets come from one `device_id` / `fp_hash`. Per-agent counts do not do it: the three agents mostly do legitimate work, and `svc-mfa-migrate` issued 500 `mfa_disabled` in two hours on day 33.
**Hides behind.** 120 legitimate support recoveries, 40% from a new device because the old one is lost; the bulk MFA re-enrolment.

## Tier C — caught by a model against the account's own baseline

### C1 · Low and slow (18 victims)
**Signature.** One fresh browser per victim (a top-five JA4), a residential IP in the victim's own city, `tz_offset` off by one to three hours, a sibling locale (`en-GB` for `en-US`, `de-AT` for `de-DE`), logins six to nine hours from the victim's usual hour. Session one: login and reads. A median of two days later: `address_added` and an order at ~2.5× the victim's median, shipped to the new address; 40% turn alerts off, never within the first thirty minutes. Victims are active accounts (15+ prior events) or dormant ones reactivated just before the real owner would have returned.
**Found by.** Round 3: an IsolationForest over 14-day deviation features (hour distance, timezone and locale shift, share of events from the usual device/network/country, novel identifiers, amount ratio, alerts off), each account scored on its worst week. Eleven of eighteen land in the top-100 queue; the seven misses have one deviation too few, or a baseline too thin. The supervised model trained on Rounds 1+2 finds almost none of them. **Round 5** reaches six of the seven, because the operator always ends the same way: a fresh browser, an address, an order at 2.5x the victim's median. The one still missing is a dormant returner with too little history under the clause (it appears at `--min-history 3`).
**Hides behind.** Night-shift users (the hour is their normal), shared-access couples (two devices, two locales, one account), travellers (timezone), new-phone upgraders (device), relocators (everything, permanently), gift buyers (amount and ship-to). No single feature separates C1 from any of these; the joint does.

## Tier D — caught by an invariant

### D · Pre-hijack (6 victims)
**Signature.** `account_created` from a datacenter with the victim's email address, `email_verification_sent`, never `email_verified`, a login or two. Ten to thirty-five days later the real person: `password_reset_requested` and `_completed` from their own device, `email_verified` (ten seconds after the reset), `payment_method_added`. Days later the attacker's remembered session resumes (`session_resume` on the original device) and orders to a new address with the victim's new card. There is no `sessions_revoked_all` anywhere.
**Found by.** Round 4, and not by an anomaly model (three land in the Round 3 queue by accident). The textbook invariant, "a password reset must end every other session", is the wrong rule for this log: 857 accounts complete a user reset and only 36 have a `sessions_revoked_all` at all, so the textbook rule flags about 820 legitimate owners. Revocation is not logged by the legitimate flows in this store, which is itself a finding for the product team. The usable invariant is built from what the log does record: a user-initiated `password_reset_completed` on an account created inside the window, with **no `email_verified` before the reset**, from a device other than the one that created the account. It flags 6 accounts, all 6 victims, no innocent one. The refinement "a `session_resume` on a pre-reset device after the reset" is the symptom, not the rule: on its own it flags 473 accounts across 13 cohorts (forgetful owners, forced resets, support recoveries), because any owner whose remember-me cookie rolls after a reset looks like a survivor. No known-history clause: these accounts are new by construction, the deliberate inversion of the Round 1 lesson.
**Time to detect.** Poor by construction. The first compromise event is the attacker's login right after sign-up, weeks before the owner appears; the invariant cannot fire until the reset. The scorer's time-to-detect line reflects that, and no detector fixes it. The control is in the reset flow: revoke every session, and log the revoke.
**Hides behind.** The two legitimate sign-ups in this log that forget their password within weeks of creating the account: they completed a reset too, but their email was verified at sign-up.

## The red herrings, in one table

| Cohort | Size | Looks like | What separates it |
|---|---|---|---|
| stuffing / spray targets | 1,500 | A1 | failures only; the account's own sessions continue from known devices |
| forced reset | 300 | A2 | `actor=system`, reason `compromised_credential_policy`, completed from a known device |
| geo-IP glitch | 150 | A3 | country changes, IP and device do not; three days, then it reverts |
| travellers | 400 | A3 / C1 | known device; a quarter change their password on the trip, with MFA |
| relocators | 60 | A3 / C1 | new country, address and phone, and it *stays*; from the known device |
| new-phone upgraders | 500 | B1 / C1 | new device, fingerprint and JA4; same network and timezone; MFA passed |
| households | 300 | B1 | one desktop shared for months with hundreds of events |
| duplicate-account owners | 80 | B3 | same provider identity, and the same old thick desktop |
| support recoveries | 120 | B4 | one ticket, one agent of forty, a known or lost device, MFA re-enrolled |
| bulk MFA re-enrolment | 500 | B4 | `svc-mfa-migrate`, two hours, 80% re-enable within four days |
| password-manager / email migrants | 400 | A1 | high-risk changes in minutes, from the known device, MFA passed |
| forgetful | 500 | A2 | failures then a self-service reset, same device |
| dormant returners | 300 | C1 | silent, then back on the known device |
| privacy browsers | 300 | B1 | fingerprint churn with no other change |
| night shift, couples | 450 | C1 | one deviation, every week, for the whole history |
| fake-account farm | 250 | B1 | young, thin clusters with **no history before the shared fingerprint** |
| QA robots | 40 | A1 / B1 | datacenter, shared device, fixed minutes, since the log began |
