# Incident Report

A post-incident report is the deliverable that turns one bad night into a
better stack. Keep it blameless and specific. This is the template the W3
capstone (W3 Ch10) expects you to fill in. `tools/incident.py` pre-fills the
detection and attack sections from the decision log; you write the rest.

```
INCIDENT ID       INC-YYYY-NN
Detected          <lab week / clock, and how: which metric or alert>
Contained         <lab week / clock>
Author            <you>

SUMMARY
<Two or three sentences: what happened, who was affected, current status.>

DETECTION
- First signal that something was wrong: <alert / metric / scoreboard row>
- Lag from first attack session to that signal: <how long>
- What fired correctly: <signals / layers>
- What missed, and why: <burned signal / stale corpus / novel profile>

ATTACK PROFILE
- Volume: <sessions, accounts reached>
- Infrastructure: <pools / ASNs / exit type>
- Evasion: <what the adversary changed to get past the last round>

CONTAINMENT (what you did, and its cost)
- Actions, each with a timestamp and a TTL: <lower block_at, campaign step-up>
- Real users affected during containment: <count, personas> (from ops.py)
- When the TTL expired / you lifted it: <clock>

LABELS PRODUCED
- Sessions a person labelled: <count> (tools/label.py)
- The feature(s) most diagnostic of this attack: <...>

REMEDIATION
- Short term: <re-weight, refresh corpus, threshold change; shipped when>
- Long term: <new signal to build, model retrain gated on the labelled set>

FALSE-POSITIVE IMPACT
- Legitimate users blocked or challenged, during and after: <count, evidence>

FOLLOW-UPS
- [ ] <owner> <action> <by when>
```
