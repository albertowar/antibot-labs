# AI Governance Record: the Lab Store detection stack (capstone reference)

> A worked reference, not the only good answer. It is what the Capstone runs under, and what the other team audits. Score it with `python tools/checkpoint.py --round 4 --record <file>` or `python tools/audit.py --record <file>`.

**Team:** capstone reference  **System:** Lab Store bot defense (W2 Ch8 scoring, W3 streaming, W4 Ch6 adversarially-hardened classifier, W4 Ch7 LLM triage, this capstone's crawl + agent governance)  **Date:** 2026-10-11

## 1. Role

We are the **deployer** of the vendor LLM used for the review summariser, the support assistant and the triage drafts, and we are **downstream** of its **GPAI** provider. We are the **provider** of the classifier we trained in-house. Vendor and model: a local open model via Ollama in production; the deterministic mock in the lab.

## 2. Purpose and risk class

The system decides whether a session is allowed, challenged, stepped up, mazed or blocked, and whether a crawl is served, priced or refused. It is **not an Annex III** use case as such. It **profiles** people (behaviour, device, egress), so we filed an **Article 6(3)** assessment at `docs/ai-act-6-3.md`; high-risk obligations apply from 2 December 2027 under the Digital Omnibus, and we review this section again by 2027-06-01.

## 3. Lawful basis

Telemetry and scoring: **legitimate interest** (fraud and abuse prevention, GDPR Recital 47), balancing test on file. **Training** the classifier on last quarter's session logs is a new purpose: compatible under **Art 6(4)** because it is the same fraud-prevention purpose and minimised, or we use **synthetic data** only (section 4). Consent is not relied on.

## 4. Synthetic data provenance

Synthetic training sessions come from the **generator** fitted in W4 Ch6, on three months of real logs (behaviour and egress class, no addresses or names). A **re-identification** check was run by a second engineer, not the generator's author, each release. Real personal data in the training set: none.

## 5. Transparency

Where an AI system interacts with a person it says so (**Art 50**): the support assistant returns an `ai_disclosure` field and an `X-AI-Disclosure` header saying it is an automated assistant and pointing to `/appeal` for a human. Challenge pages do not pretend to be a person. AI-generated decoy content is served only to refused traffic and never to a person.

## 6. Automated decisions and appeal

A block has a significant effect, so it is an **Article 22** decision. The **appeal** path is `/appeal`, reviewed by a **human** within 24 hours; a contested block is **reinstated** by default after 72 hours without review. Appeals are counted per cohort and reported in section 9.

## 7. Human oversight

The on-call engineer can switch any model to **shadow mode** or off within minutes by lowering `DEFENSE_LEVEL`, no deploy needed. The LLM triage never blocks on its own: it proposes, the **gate** filters, and a named person **approves** each rule with `tools/approve.py` (the only writer of `rules/active.json`). The **kill switch** is tested each release.

## 8. Logging and retention

Each decision logs score, action, level, model and prompt version, signals, and nothing more. **Retention: 90 days**, published at `/.well-known/governance.json` and enforced by `/admin/purge`; the deletion job runs daily. Model and prompt versions are kept for the life of the model.

## 9. Evaluation and red team

Before any release: the W4 Ch6 **adversarial** suite, **false positives per cohort** against the 2% budget (shopper, shared-IP, VPN, privacy, a11y, agent shopper, signed cloud agent, assistive agent), and **drift** checks every 7 days. Last red-team date on file with the model version (section 8).

## 10. Third-party models and prompts

Data sent to the **vendor** model per request: the product name, price, the question and the published review text, never raw fingerprints, addresses or names. **Prompt-injection** controls: spotlighting plus output validation (`llm_guard.py`). **System prompts** are under change control; a prompt change is a release (section 9).

## 11. Deception limits

Tarpits, labyrinths and decoys are served **only to sessions the policy would otherwise block**, never to a crawler honouring the machine-readable reservation and never to a session using the accessibility API. Decoy content never leaves the lab and is never designed to harm a third party's model or a person. Owner: the anti-abuse lead.

## 12. Incidents and complaints

A **complaint** from a person, a vendor, an accessibility auditor or a **regulator** (DPA or AI Office) goes to `abuse@lab-store.test` and is acknowledged **within 2 business days**. A **false-positive incident** (a cohort over budget in production) is declared by the on-call engineer, reviewed within 24 hours, and written up with the W3 Ch8 disclosure template.

| Name | Team | Signature | Time |
|---|---|---|---|
| Reference | Anti-abuse | — | 2026-10-11 |
