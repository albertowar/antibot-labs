# Incident Report INC-2026-05

*Auto-filled from the decision log for lab week 5. Replace every <...> with your judgement.*

## SUMMARY
<two or three sentences>

## DETECTION
- Attack began around lab clock 3029280 (week 5).
- Bot sessions this week: 120. Reached a valid account: 42. Not acted on at all: 120.
- Signals that fired on the attack: mouse_too_straight 1, ip_elevated 1.
- Signals that missed: the sessions above show how little fired; name the burned/blind signal here.
- Lag from first attack session to the alert that caught it: <fill in from ops.py / alerts.py>.

## ATTACK PROFILE
- Volume: 120 sessions, 42 accounts reached.
- Infrastructure (network kind and ASN): residential AS64496 120.
- Evasion: <what changed from the previous week>.

## CONTAINMENT (and its cost)
- Real users blocked or challenged this week: 16 of 220: cgnat 6, vpn 3, cgnat+typo 3, a11y+autofill 1, cgnat+autofill 1, vpn+typo 1, privacy+cgnat 1.
- Actions taken, each with a timestamp and a TTL: <tools/contain.py ...>.

## LABELS PRODUCED
- Sessions a person labelled: <count> (tools/label.py).

## REMEDIATION
- Short term: <re-weight / refresh corpus / threshold>.
- Long term: <new signal; retrain gated on the labelled set>.

## FALSE-POSITIVE IMPACT
- 16 legitimate users affected this week (see personas above).

## FOLLOW-UPS
- [ ] <owner> <action> <by when>
