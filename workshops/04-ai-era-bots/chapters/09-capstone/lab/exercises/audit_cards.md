# Round 4: Audit Cards (🔴 the other team), against the LIVE store

Swap governance records with the other team, then run them against the running store. You are now the auditor: a data-protection authority, the AI Office, an accessibility inspector, or the opposing counsel in an agentic-commerce dispute. Pick cards, read the draft, and answer each one with **"answered"**, **"vague"** or **"the record doesn't say"**, citing the section number. Every "doesn't say" is a hole they take into the Capstone. Five minutes; the blue team then has three minutes to patch.

Keep it honest. The aim is a record that survives an audit, not a trick.

> `python tools/audit.py` runs cards 1-7 automatically against the live store; the cards below are the human read of the record behind each one. Score a record with `python tools/audit.py --record <file>`.


| # | Card | Which section should answer it |
|---|---|---|
| 1 | Your classifier was retrained last month on three months of real session logs. Those people consented to fraud prevention, not to being training data. Lawful basis for the training? | 3 (lawful basis), 4 (synthetic alternative) |
| 2 | The appeal assistant is an LLM. A blocked customer spent twenty minutes "talking to support". Where does it say it is an AI, and how do they reach a person? | 5 (transparency), 6 (appeal) |
| 3 | Your synthetic-data generator was fitted on real sessions including addresses. Who checked that it does not reproduce them? | 4 (provenance) |
| 4 | A screen-reader user driving an assistive agent was blocked three times this week. Which number in your record would have shown that, and who looks at it? | 9 (per-cohort evaluation), 6 (appeal) |
| 5 | The LLM triage step started blocking on its own after a prompt change on Friday night. Who approved the prompt change, and how fast can it be switched off? | 10 (prompt change control), 7 (oversight) |
| 6 | You serve an AI-generated labyrinth to suspected crawlers. A Code of Practice signatory that honoured your reservation got it too, for an hour, after a rule mistake. Did your record allow that? | 11 (deception limits) |
| 7 | A shopper's agent placed an order the shopper says they never confirmed. Which log line shows the human confirmation step, and how long do you keep it? | 8 (logging), 6 (appeal) |
| 8 | Your vendor LLM receives the full session, fingerprints included, in the prompt. Where does the record say what leaves to the vendor? | 10 (third-party models) |
| 9 | The AI Office asks whether your scoring system is high-risk. You say no. Where is the written Article 6(3) assessment, and when is it next reviewed? | 2 (risk class) |
| 10 | A journalist asks whether the store uses AI to decide who gets in. What is the answer, and who gives it? | 5 (transparency), 12 (complaints) |
| 11 | A cohort went over the 2 % blocked budget for a week before anyone noticed. Is that an incident in your record? Who declares it? | 12 (incidents), 9 (drift) |
| 12 | Decoy product pages you generated to poison scrapers were ingested by a research crawler and published in a dataset. Who owns that outcome? | 11 (deception limits) |

## Scoring the exchange

| Outcome | Points |
|---|---|
| Card answered by a specific section with a name, a number or a place | +1 blue |
| Card answered only by a vague phrase ("we comply with applicable law", "as appropriate") | +1 red |
| Card the record does not address | +2 red |
| Blue patches a hole within the three minutes with a concrete rule | +1 blue |

Target for a team's record: 10 of the 12 checklist items covered (`python tools/checkpoint.py --round 3 --record`), and no card left in the "doesn't say" column.
