# Round 1: Three Cease-and-Desists

Three fact patterns. In each one, the store you have been defending all week has sent a cease-and-desist letter and is deciding whether to sue. You play both sides, or split the roles with a peer: **🔵 counsel for the store** and **🔴 counsel for the scraper**. Nobody here is a lawyer and nothing in this lab is legal advice; the point is to know which claims a lawyer would take seriously, because that decides what your detection stack has to prove.

**Format:** read the cases, fill the verdict sheet (alone as both counsels, or in a pair with one 🔵 and one 🔴), then reveal against the answer key.

**Scoring:** for each case, list every claim you think **survives** (would get past a motion to dismiss in the stated jurisdiction). +1 for each claim that matches the key, −1 for each claim the key marks as weak. The pair with the best net score wins, and ties go to the pair that cited the most recent case.

---

## Case A: The public listings (US, no login)

PriceWatch Inc. scrapes the store's public product pages (names, prices, stock status, descriptions, product photos) at roughly 50,000 requests a day. No account, no login. The store blocked PriceWatch's cloud IP ranges; PriceWatch moved to residential proxies. The store added a proof-of-work challenge in front of the catalogue; PriceWatch automated solving it. The store sent a cease-and-desist letter naming the Terms of Service (a "browsewrap" link in the footer) and demanding that PriceWatch stop. PriceWatch kept going. The store's engineering team spent about 60 hours over two months building and tuning the defenses and tracing the traffic.

**🔵 Store's counsel claims:** (1) CFAA, access without authorisation after the cease-and-desist; (2) breach of the Terms of Service; (3) DMCA §1201(a), circumventing the proof-of-work challenge; (4) trespass to chattels.

**🔴 Scraper's counsel asks:** Was any gate ever down? Is a footer link a contract? Is a price a copyrighted work? What did the store actually lose?

---

## Case B: The logged-in reseller (US, clickwrap, GraphQL)

DataFeed LLC created about 400 member accounts with invented names and disposable email addresses, clicked "I agree" to the Terms of Service on each one, and used the GraphQL API behind the login to pull member-only pricing, inventory levels and the recommendation feed. It resells that feed to competitors. The store terminated the accounts and sent a cease-and-desist. DataFeed created new accounts and continued, this time also bypassing the login step-up challenge with a CAPTCHA-solving service. The store's incident response and forensic work cost about $40,000, documented in invoices and timesheets.

**🔵 Store's counsel claims:** (1) breach of contract; (2) CFAA, access without authorisation after termination and revocation; (3) DMCA §1201(a), circumventing the step-up challenge; (4) fraud, for the fake accounts.

**🔴 Scraper's counsel asks:** Did the terms survive account termination? Is pricing a trade secret or just data? Is a CAPTCHA an "effective" technological measure if a $2 service solves it?

---

## Case C: The people search (EU, no login)

Profilr, a startup in Ireland, scrapes the store's public review pages. Reviews carry the reviewer's display name, an avatar photo, a city and the text of the review. Profilr merges them with data from other sites into searchable profiles of named individuals and sells access. There is no login and no CAPTCHA on the review pages. The store's Terms of Service forbid automated access. Irish and German customers have complained to the store that their reviews now appear in Profilr search results. The store sent a cease-and-desist and is deciding whether to sue, and is also worried about its own exposure.

**🔵 Store's counsel claims:** (1) breach of the Terms of Service; (2) a CFAA-style unauthorised-access claim (the store has a US parent); (3) GDPR, against Profilr, as a controller with no lawful basis; (4) that the store itself has done nothing wrong.

**🔴 Scraper's counsel asks:** Isn't the data public? Didn't the reviewers choose to post it? And who left it scrapable without any protection at all?

---

## Verdict sheet (one per pair)

| Case | Claim | Survives? (Y/N) | One-line reason, with the case or statute you rely on |
|---|---|---|---|
| A | CFAA | | |
| A | Contract (browsewrap ToS) | | |
| A | DMCA §1201 | | |
| A | Trespass to chattels | | |
| B | Contract (clickwrap ToS) | | |
| B | CFAA | | |
| B | DMCA §1201 | | |
| B | Fraud | | |
| C | Contract | | |
| C | CFAA-style | | |
| C | GDPR against Profilr | | |
| C | "The store has no exposure" | | |

When the key is revealed, count your net score, then answer the question that carries into Round 2: **in each case, what would the store's detection logs have needed to contain for the surviving claims to be provable?**
