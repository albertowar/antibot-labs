# W4 Ch6 lab walkthrough: how the reference detectors reason

Read this after you have tried a round, not before. Each section says what the reference uses, why each
part is there, and which cohort each part protects. The thresholds are in the solution scripts; the
numbers they produce are in the README's expected-results table.

The campaigns in this dataset exist only as the traces an operation leaves on a platform. Nothing here
describes how to run one.

## Round 1: account and profile rules (`round1_profile.py`)

**What it flags:** an account that was at most a week old when it first messaged a stranger, sent at least
15 first contacts inside some 48 hours, and either shares an uploaded photo with two or more other
accounts or signed up from a hosting or VPN network.

**Why all three families.** Each one alone describes honest members:

| Part alone | Who it hurts | Why |
|---|---|---|
| new + burst | newcomers | they joined at the trail festival and messaged everyone they met |
| photo shared by 3+ accounts, counting defaults | default-avatar members | everyone who never uploaded a photo shares one of six |
| hosting/VPN egress | VPN users | privacy-minded members, some on cloud VPNs |

The farm is the intersection: new and bursting and on infrastructure it reuses. The rule still flags a
few newcomers who signed up on the festival's cloud-hosted Wi-Fi; that is the round's honest cost.

**What it misses, by design:** everything that bought aged accounts and uploads a fresh photo per persona.

## Round 2: conversation shape (`round2_shape.py`)

**What it adds:** an account that opened ten or more conversations, sends at least 95% of its messages
inside one ten-hour UTC block, and moved at least 15% of the conversations it opened to another app within
a week.

**Why the shift matters.** One crew of operators works every persona, so every persona keeps the same ten
hours, seven days a week, whatever time zone its profile claims. Real members keep the hours of the place
they live, so their messages spread over about sixteen waking hours.

| Part alone | Who it hurts | Why |
|---|---|---|
| fan-out + early "text me" | gear sellers | they message people who liked a listing and ask them to text |
| shift hours + fan-out | guides | they answer questions in office hours and send announcements |
| translated messages | translation users | the built-in translator is how non-native members talk |

The reference never reads translation and never reads text. One guide runs a summer trip's group chat on
another app and invites people from the announcements; the rule flags that guide, the round's honest cost.

**What it misses, by design:** a human closer working a handful of targets at human pace, and a crew that
spreads one or two targets across many accounts.

## Round 3: interventions (`round3_interventions.py`)

**Hold** a first payment when a new contact the payer has really talked to (ten or more messages, a
conversation at least three days old) asked them to move to another app, and the money goes to that
contact or to a payout handle the platform first saw recently. **Warn** on any other first payment to a
recently created payout handle.

**Why "bonded" and "three days".** Commerce is quick: a buyer pays a seller within a day or two of the
first message. A scam's first payment comes after the bond. And a one-line promo that said "text me" is not
who the payer is paying, so the contact must be someone they actually talk to.

**The honest costs:** three long-distance couples who met this summer and moved to another app, whose first
gift is held; and newcomers moving festival-sale money to their own new bank handle, who see a warning.
Knowing that a handle belongs to the payer would remove the second; nothing in this data removes the first.

**What it misses, by design:** the dispersed crew mostly never asks to move apps on-platform, so its victims'
payments have no contact to attribute; they get only the warning.

## Round 4: reports, partner intel, clustering (`round4_network.py`)

**Seeds** (evidence of scam): two or more distinct members reported the account for a scam; the account
mentioned a handle or domain on the partner bank's list; or two or more payers of a listed handle had it as
the new contact they talk to most.

**Edges** (association only): a shared device, a shared non-community link domain, and members whose victims
(two or more each) paid the same recently created handle.

A connected component is taken down only if it contains a seed and is no bigger than any crew could be.

| Shortcut | Who it hurts | Why |
|---|---|---|
| cluster on shared devices without a seed | households | families share one tablet |
| treat every listed indicator as a verdict | a seller | one listed handle is an honest seller's, after a chargeback |
| money edges through any handle, any contact | sellers | long-lived seller handles and one-line promos link every seller who promoted to the same buyers |

The reference still flags the seller with the disputed chargeback and the seller with two dispute reports.
Both are within budget, and both are why a takedown queue gets a human review before anyone is banned.
