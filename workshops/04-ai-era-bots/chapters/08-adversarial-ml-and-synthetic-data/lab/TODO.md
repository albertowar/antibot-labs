# W4 Ch8 Adversarial ML & Synthetic Data: what is left

Status as of 2026-10-15. The lab was migrated onto the W4 starter (contract 1.6) in `ed0157c0`
and re-based onto contract 1.7 (`Round.setup`/`Round.people` replace the `labclient.reset`/
`catch_up` monkeypatches; `defenses/netinfo.py` is the starter's; the `oracle_guard` and
`robust_train` stubs were re-authored — the migration had committed the solutions over them).
Smoke, `check_labs.py`, Rounds 0–2 and the compose path verify.

## Open

- [ ] **P1 · Rounds 3–4 do not reproduce from a fresh environment.** Same disease as W2 Ch7
  (this lab extends that pipeline), which was **fixed 2026-10-18**: its features read each
  session's virtual clock (`X-Virtual-Ts`, set in `tools/shopper.py`, recorded by the store)
  instead of measured wall gaps, so a regenerated history trains a byte-identical model (see
  `workshops/02-proficient/chapters/07-machine-learning-for-bot-detection/lab/defenses/features.py`).
  Here the same disease remains: the features embed measured wall-clock durations, so the v4
  (provenance-sanitized) and v5 (augmented) models trained from a regenerated history land off
  their budget bands. Measured 2026-10-15 fresh: round 3 evade 52% succeeded (budget ≤20%),
  round 4 reseller 100% (budget ≤25%); rounds 0–2 passed. Port the same move as W2 Ch7 —
  deterministic virtual-time features (or band-based judging), since the feature
  families are shared lineage.
- [ ] **P2 · The README's Round 1 "Budget" column does not name the checkpoint's gates.** The
  measured expected-results row says `≤10% · ≤10% · 10–60%` for baseline / cheap / patient,
  but `tools/checkpoint.py` judges Round 1 on the baseline rate (≤10%) plus the *clone's share
  of the allowed region* (cheap ≤50%, patient ≥90%) — two different metrics under one column
  heading. The README's Rounds table (filled 2026-10-18) states the checkpoint's real gates;
  align the expected-results column naming with them the next time the table is regenerated.
