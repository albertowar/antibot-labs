# AI-Era Ethics Checklist for Bot Defense

Use this before shipping a defense that uses AI, blocks AI, or both. It extends the W3 Ch8 checklist (authorisation, proportionality, the dual-newspaper test), which still applies.

## Before you block an agent

- [ ] Is the thing I am blocking a program acting for itself, or a person acting through a program? After *Amazon v. Perplexity* (9th Cir. 2026) the second one is legally the person.
- [ ] Does my policy give a declared, well-behaved agent a way in? If not, I am teaching agents not to declare.
- [ ] Have I measured the assistive-technology cohort separately, and is its challenge path non-visual?
- [ ] Is the money step confirmed by a human? Whose dispute is it when it is not?
- [ ] Do my terms say anything about agents at all, and did anyone click them?

## Before you reserve against a crawler

- [ ] Is my reservation machine-readable on at least two channels, or is it a paragraph in the terms?
- [ ] Have I separated access rules from usage preferences, so that search stays open?
- [ ] Do I log enough to make a complaint or a claim, and not so much that the log is the next breach?
- [ ] Have I written down what one day without search traffic costs before I ship `Disallow: /`?

## Before you deceive a crawler

- [ ] Is the decoy served only to traffic I would otherwise block, and never to a crawler that honoured my signals?
- [ ] Can the decoy content harm anyone other than the operator of the crawler? (A poisoned dataset is published to everyone.)
- [ ] Is anyone deceived who is a person rather than a program?

## Before you put AI in the defense

- [ ] Can the model block on its own? Should it? Who switches it off, and how fast?
- [ ] What did I train it on, under which lawful basis, and would the people in that data recognise the purpose?
- [ ] Where it talks to a person, does it say it is a machine?
- [ ] Which number would show me it is wrong about a protected cohort, and who looks at it every week?
- [ ] What goes to the vendor's model in the prompt, and what comes back into my decision?

## The dual-newspaper test, AI edition

Would the defense read well in the paper under "store blocks disabled customers' assistive software"? Would it read well under "store's AI quietly trained on everyone's browsing"? If either headline is fair, it is not finished.
