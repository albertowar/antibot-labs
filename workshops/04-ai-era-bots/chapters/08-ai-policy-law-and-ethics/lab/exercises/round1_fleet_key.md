# Round 1: Fleet Key (instructor)

Current to October 2026. Six crawler types, what each one reads, and what reaches it when it ingests anyway. Nothing here is legal advice; the point is to know which signal is a reservation, which is a request, and which is evidence.

| Crawler | Reads | Honours | If it ingests anyway, your lever | What the lever needs from your logs |
|---|---|---|---|---|
| **gpai_signatory** (training crawler of a GPAI Code of Practice signatory) | robots.txt for its token and `*`; Content-Signal `ai-train`; Content-Usage `train-ai`; TDM-Reservation header; RSL licence link | Any machine-readable reservation. Not natural-language terms. | It only ingests when it saw nothing. That is a reservation defect, not a claim. | Nothing: fix the stack. |
| **search_answers** (search crawler that also feeds AI answers) | robots.txt for its token; `ai-train` / `train-ai` | Training: yes. Answers: no; `ai-input=no` is read, not acted on. A `Disallow` for its token stops both, and search. | None reliable. The trade is search visibility against answer ingestion. | — |
| **research_tdm** (university TDM crawler) | robots.txt | `Disallow` as politeness. An Art 4 reservation has no effect: research TDM is DSM Directive **Art 3**, which cannot be reserved against. | None. Lawful. | — |
| **stealth_crawler** (undeclared, Chrome UA, rotating cloud ASNs) | Nothing. Never fetches robots.txt. | Nothing. | **AI Act Art 53(1)(c)** complaint to the AI Office if you can attribute it to a GPAI provider (the Code's copyright chapter commits signatories to honour RFC 9309 and reservations). **DMCA §1201** if it solved a challenge guarding copyrightable content (*Reddit v. SerpApi*, S.D.N.Y. 2026, W3 Ch8). Contract only if it used an account that clicked. | `user_agent`, `asn`, `robots_fetches` (to show it never asked), `challenge_outcomes`; retention ≥ 30 days. |
| **scraping_intermediary** (scraping-as-a-service vendor) | robots.txt | Nothing. Solves challenges, resells. | **DMCA §1201** for solved challenges; **contract** if clickwrap accounts; **GDPR** if personal data (reviews, names) was taken (W3 Ch8 Case C). | `user_agent`, `asn`, `challenge_outcomes`; retention ≥ 30 days. |
| **pirate_mirror** (ingests from a mirror or a shadow dataset) | Nothing. Never visits. | Nothing. | **Copyright against the ingestor.** *Bartz v. Anthropic* (N.D. Cal. 2025; $1.5 B settlement approved July 2026): training may be fair use, keeping pirated copies was not. The Art 53(1)(d) public training summary is where you look for your catalogue. | None of yours. Registered works and the provider's summary. |

## Expected scoreboards

| Stack | Machine-readable? | Honoured | Ingested | Search | Reachable ignorers with evidence |
|---|---|---|---|---|---|
| `reservation_naive` (one named token, browsewrap, 7-day logs) | **No** | 0/6 | 6/6 | kept | 0/2 |
| The usual first edit: `User-agent: *` / `Disallow: /` | Yes (robots wildcard) | 3/6 | 3/6 | **lost** | 0/2 (logging unchanged) |
| `reservation_reference` | Yes (6 channels) | 2/6 (signatory; search for training) | 5/6 | kept | 2/2 |

The five that still ingest under the reference stack are the point of the round: the search crawler for answers under a signal it does not act on, the research crawler lawfully, the stealth crawler and the intermediary with your evidence against them, and the mirror out of reach of anything you emit.

## The two mistakes to catch

1. **Reserving by name.** A robots.txt that lists vendor tokens is complete for one afternoon. Reserve by *usage* (`ai-train`, `train-ai`, TDM header) and let access rules do access.
2. **Blocking search to block answers.** `Disallow: /` for `*` removes the search crawler, the research crawler and the signatory, and none of the three you were worried about. Write down what one day without search traffic costs before you ship it.
