# Chapter 6 Lab: Session Trust & Sensitive Actions

Starts from: `workshops/03-advanced/starter/` (contract 1.8). Adds: see the block below.

<!-- lab-diff:start -->
**Adds** (files not in the starter):

- `defenses/blanket_otp.py`
- `defenses/breachcorpus.py`
- `defenses/breached_passwords.py`
- `defenses/change_hold.py`
- `defenses/login_stack.py`
- `defenses/login_throttle.py`
- `defenses/ratelimit.py`
- `defenses/rba_score.py`
- `defenses/recovery_risk.py`
- `defenses/session_trust.py`
- `defenses/stepup_channels.py`
- `defenses/stepup_policy.py`
- `defenses/sudo_reauth.py`
- `defenses/trustlib.py`
- `demo_site/ext/rba.py`
- `demo_site/ext/rba_world.py`
- `demo_site/ext/session_trust.py`
- `demo_site/ext/session_world.py`
- `tools/personas_ch6.py`

**Edits** (student and tuning files):

- `defenses/ladder.py`
- `defenses/policy.py`
- `tools/checkpoint.py`
<!-- lab-diff:end -->

**Format:** five rounds (0 to 4), wire-it. Rounds 1 to 4 are stubs with `TODO (Round N)` in
`defenses/sudo_reauth.py`, `defenses/session_trust.py`, `defenses/stepup_channels.py` and `defenses/change_hold.py`,
and their finished versions in `solutions/roundN/`. `python tools/checkpoint.py --round N --catch-up` installs them.

**Status: in progress.** The store side, the 80 account holders and the defenses are built and measured below.
The attacker side is not: the three crews (`demo_site/ext/session_world.py`) have no attack scripts and no
scored profiles yet, so each round's checkpoint measures what the defense costs real customers and not yet what
it stops. The chapter's `TODO.md` says why and what is left.

## Rules of engagement

- **Local only, enforced in code.** Every tool reaches the store through `tools/labclient.py`, which asks
  `labnet.py` at the lab root for `DEMO_URL` and refuses anything that is not this machine (side-service URLs
  such as `REDIS_URL` too). The store's edge accepts the lab headers only from loopback.
- **Synthetic everything.** The accounts are the store's seeded users; the phones are fictional `+1-555-01xx`
  numbers whose texts land in the lab mailbox; the "enrolled app" is a lab inbox per account
  (`/lab/devices/<uid>`). Source addresses are rented from `data/world.json` (documentation ranges). No real
  people, credentials, phone numbers or services.
- **Outbound network:** none during the rounds. Only setup needs the internet: installing packages and
  container images.

## Setup

```bash
python3.12 -m venv .venv && . .venv/bin/activate        # one venv per chapter
pip install -r requirements.txt
python tools/doctor.py
python demo_site/app.py                                  # or let tools/checkpoint.py start nothing: run it next to this
```

The general setup (toolchain, the store, the smoke test) is `onboarding/setup/PREWORK.md`; this lab needs
nothing beyond it.

## What is in the lab

- **Chapter 5, finished** (`shared.json`, byte for byte): the per-user login risk score, the step-up policy,
  recovery scoring, and W2 Ch6's throttle and breach screen. They run at every level as the login in front of
  everything this chapter adds (`defenses/login_stack.py`).
- **`demo_site/ext/session_trust.py`**: the trust inputs every gated request carries (`ctx.attrs["st"]`, built
  from the store's `ctx.auth` stamp), the step-up types `sudo`, `otp_session`, `sms_otp`, `device_confirm` and
  `kba` (all registered with `reauth=True`; none of them writes `uid`), the lab clock, the notification fan-out
  to the old email, the phone and the enrolled app, and the resolver that releases or cancels held changes.
- **The lab clock.** One lab second stands for `LAB_CLOCK_DIVISOR` (120) real seconds, so NIST SP 800-63B-4's
  AAL2 limits (24 hours overall, 1 hour idle) become 720 and 30 lab seconds. `POST /lab/clock` advances it.
- **`tools/personas_ch6.py`**: 80 account holders, Chapter 5's sign-ins, each with one thing to get done after
  signing in.

| Persona | n | Goal | Sensitive action (weight) |
|---|---|---|---|
| routine | 32 | buy to the saved address with the saved card | none (0) |
| mover | 10 | add a new address, ship an order to it | `address_add` (50), new ship-to (60) |
| gift_giver | 8 | redeem a gift card | `gift_card_redeem` (60) |
| card_expired | 6 | replace the saved card | `card_add` (60) |
| cgnat_phone | 6 | add a second address, from the phone | `address_add` (50) |
| rotator | 4 | change the password | `change_password` (75) |
| traveller | 4 | ship an order to the hotel | new ship-to (60), from abroad |
| new_phone | 4 | replace the saved card from the new phone | `card_add` (60), a device the store never saw |
| shared_family | 3 | redeem a gift card on the family laptop | `gift_card_redeem` (60), no phone or app on file |
| no_inbox | 3 | change the email (the old inbox is gone) | `change_email` (75), cannot read an emailed code |

## Rounds

| Round | Level | Defense | Aimed at (crew) | Who pays |
|---|---|---|---|---|
| 0 | 0 | Chapter 5's login stack; nothing guards the session after it | — | nobody beyond Chapter 5's login code |
| 1 | 1 | Sudo mode: the password again before every weighted action | the session-cookie crew (no password) | everyone with a sensitive goal types a password |
| 2 | 2 | Session trust, action weights, a restricted session, an emailed code to step up | the remembered-device crew | `no_inbox` cannot reach the email change |
| 3 | 3 | Step-up by possession: the enrolled app or an SMS; knowledge questions when neither is on file | the webmail crew | `shared_family` fails the questions about its own account |
| 4 | 4 | Knowledge answers demoted to a signal; no strong factor means a cooling-off and a notice; low-trust orders to new addresses held | (the residual is a crew that only reads) | the ones Round 3 refused now wait instead |

Run one: `python tools/checkpoint.py --round 2` (start the store first), or let `python tools/verify.py --round 2`
start one on a free port. `--catch-up` installs `solutions/round1..N`; `--restore` puts your files back.

## Expected results (self-check)

Generated by `python tools/verify.py --write-readme`; do not edit by hand. Each round runs the 80 account holders
and the starter's 40 shoppers; "friction" is account holders who met a step-up or a hold at their goal, against
`policy.FRICTION_BUDGET` (25%). Each round prints its friction line before the verdict; Round 1 reports it without
judging it (sudo mode's cost is the point of that round). The Attack columns stay empty until the attacker side lands.

<!-- results:start -->
| Round | Attack | Before (level N-1) | After (level N) | Shoppers stopped after |
|---|---|---|---|---|
| 0 | — | — | — | none |
| 1 | — | — | — | none |
| 2 | — | — | — | no_inbox 3 |
| 3 | — | — | — | no_inbox 1, rotator 1, shared_family 2 |
| 4 | — | — | — | none |
<!-- results:end -->
