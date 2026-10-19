# Round 3: Loophole Cards (🔴 red team)

Take a rules-of-engagement draft that is not yours: a peer's, or, working alone, your own draft read as the opponent. Pick cards, read the draft, and answer each one with **"allowed"**, **"forbidden"** or **"the document doesn't say"**, citing the section number. Every "doesn't say" is a point for you and a hole in their document. The blue team then patches.

Keep the answers honest. The aim is a document that survives the Capstone, not a trick.

| # | Card | Which section should answer it |
|---|---|---|
| 1 | The opponent's Redis is on `127.0.0.1:6379` with no password. Reading their rate-limit counters directly would tell us exactly when to burst. In scope? | 4 (prohibited), 2 (in-scope targets) |
| 2 | Our scraper uses an online CAPTCHA-solving service to get past their step-up challenge. That's a third-party service, but the *target* is in scope. Allowed? | 3 (out of scope), 6 (synthetic data: whose images go to the service?) |
| 3 | We captured their decision log during the attack. After the workshop we'd like to train our own classifier on it. Allowed? | 7 (data handling) |
| 4 | Their proof-of-work endpoint is slow. We want to send 2,000 requests per second for ten minutes "to measure the ceiling". Allowed? | 5 (traffic limits), 4 (DoS) |
| 5 | We found Flask running with `debug=True` on their stack. The debugger console gives us code execution. Use it? | 4 (host exploitation) |
| 6 | As defenders, we'll tarpit every request from the opponent's address range for 45 seconds each. Allowed? | 8 (deception limits) |
| 7 | We'd like to post the opponent's bypass on the team blog tonight, with their team name, as a write-up. Allowed? | 10 (disclosure) |
| 8 | The step-up flow emails a code. A teammate offers their real address to make it "realistic". Allowed? | 6 (synthetic data) |
| 9 | A free residential-proxy trial would let us test from "real" home addresses instead of the documentation ranges. Allowed? | 2 (source addresses), 3 (internet hosts) |
| 10 | The opponent's defense blocked our simulated Tor cohort 100%. We claim that as a scoring win for us. Does their document say how that is scored? | 11 (false-positive accountability) |
| 11 | Midway through, the opponent's stack stops responding. We're not sure whether it's our traffic or their redeploy. What do we do, and who decides? | 9 (stop conditions), 12 (referee) |
| 12 | We discovered a real vulnerability in the shared workshop code that every team runs. Who do we tell, and when? | 10 (disclosure) |

## Scoring the exchange

| Outcome | Points |
|---|---|
| Card answered by a specific section | +1 blue |
| Card answered only by a vague phrase ("be reasonable", "act ethically") | +1 red |
| Card the document does not address | +2 red |
| Blue patches a hole within the two minutes with a concrete rule | +1 blue |

Target for a team's document: 10 of the 12 checklist items covered (`python tools/checkpoint.py --round 3 --roe`), and no card left in the "doesn't say" column.
