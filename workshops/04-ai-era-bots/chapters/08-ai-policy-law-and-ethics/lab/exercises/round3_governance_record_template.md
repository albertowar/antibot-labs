# AI Governance Record: the store's detection stack (draft)

> Fill in every section. This record is what you hand an auditor, a data-protection authority or the AI Office when they ask what the AI in your bot defense does, and it is the charter under which the Workshop 4 Capstone ("Govern the Agents") runs. An auditor will read it for the hole. Score a draft with `python tools/checkpoint.py --round 3 --record <this file>`.

**Team:** _______________ **System:** store bot defense (W2 Ch8 scoring, W3 streaming, W4 Ch6 adversarially-hardened classifier, W4 Ch7 LLM assist) **Date:** _______________

## 1. Role

For each AI component, are we the **provider** or the **deployer** under the AI Act? Classifier (ours, trained in-house): _______________. LLM used for triage and the appeal assistant (third-party model, API): _______________; its provider is a GPAI provider and we are **downstream**. Vendor and model name: _______________.

## 2. Purpose and risk class

The system decides whether a session is allowed, challenged, stepped up or blocked. It is not an Annex III use case as such. It **profiles** people (behaviour, device, location), so we documented an Article 6(3) assessment: _______________ (where). High-risk obligations apply from 2 December 2027 under the Digital Omnibus; we review this section again by _______________.

## 3. Lawful basis

Telemetry and scoring: legitimate interest (fraud and abuse prevention, GDPR Recital 47), balancing test on file at _______________ (W3 Ch8). **Training** the classifier on last quarter's session logs is a new purpose: compatible under Art 6(4) because _______________, or we use synthetic data only (section 4). Consent is not relied on.

## 4. Synthetic data provenance

Synthetic training sessions come from _______________ (generator, W4 Ch6). The generator was fitted on: _______________ (real logs? which fields? how old?). Re-identification check performed by _______________ on _______________. Real personal data in the training set: none / the following fields: _______________.

## 5. Transparency

Where an AI system interacts with a person, it says so (Art 50): the appeal assistant tells the user it is an AI and how to reach a human: _______________ (exact wording). Challenge pages do not pretend to be a human. AI-generated decoy content (section 11) is labelled in a way a declared crawler can read: _______________.

## 6. Automated decisions and appeal

A block has a significant effect on the person. Appeal path: _______________ (URL / channel), reviewed by a **human** at _______________ within ______ hours. A contested block is reinstated by default after ______ hours without review. Appeals are counted per cohort and reported in section 9.

## 7. Human oversight

The on-call engineer _______________ can switch any model to **shadow mode** or off within ______ minutes without a deploy. The LLM triage never blocks on its own; it proposes, the score decides, and _______________ reviews its proposals weekly. Kill switch tested on: _______________.

## 8. Logging and retention

Each decision logs: score, action, model version, prompt version (for LLM steps), signals, and nothing more. Retention: ______ days, deletion job _______________. Prompts and LLM outputs are kept for ______ days. Model and prompt versions are kept for the life of the model plus ______.

## 9. Evaluation and red team

Before any release: the W4 Ch6 adversarial suite (_______________), false positives per cohort against the 2 % budget (shopper, VPN, agent shopper, signed cloud agent, undeclared cloud agent, assistive agent), and drift checks every ______ days. Last red-team date: _______________. Results are kept with the model version (section 8).

## 10. Third-party models and prompts

Data sent to the vendor model per request: _______________ (never raw fingerprints, addresses or names). Prompt-injection controls (W4 Ch5, Ch7): _______________. System prompts are under change control at _______________; a prompt change is a release (section 9).

## 11. Deception limits

Tarpits, labyrinths and decoys are served only to sessions the policy would otherwise block, never to a crawler honouring a machine-readable reservation and never to a declared agent that followed the terms. Decoy content never leaves the lab and is never designed to harm a third party's model or a person. Owner: _______________.

## 12. Incidents and complaints

A complaint from a person, a vendor, an accessibility auditor or a regulator (DPA or AI Office) goes to _______________ and is acknowledged within ______ business days. A false-positive incident (a cohort over budget in production) is an incident: declared by _______________, reviewed within ______ hours, written up using the W3 Ch8 disclosure template.

| Name | Team | Signature | Time |
|---|---|---|---|
| | | | |
| | | | |
| | | | |
