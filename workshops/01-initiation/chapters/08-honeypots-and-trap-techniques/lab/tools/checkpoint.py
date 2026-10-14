"""
Round checkpoint for Chapter 8 (Honeypots & Trap Techniques). Declares the rounds and hands over to
checkpoint_core.

    python tools/checkpoint.py --round 2              # set level 2, run the round's attacks next to the shoppers
    python tools/checkpoint.py --round 2 --level 1    # the same attacks against Round 1's defenses (the "before")
    python tools/checkpoint.py --round 2 --catch-up   # install solutions/round1..2 first
    python tools/checkpoint.py --restore              # put your own files back (the .bak copies)
    python tools/checkpoint.py --all --markdown       # every round (the reference table)

Every round measures two things: what each bot really got, and which of the 40 shoppers the traps
caught by mistake. The first needs the server's word. A trapped signup gets a fake success, so a bot's
own count ("10/10 succeeded") is what it BELIEVES; `truth()` below replaces it with what the decision
log says the store really did (accounts created, reviews published). The shoppers run the `signup`
scenario (tools/personas_ch8.py): a shopper is hurt if a trap or sanction signal touched anything they
did, even when the page looked fine. A round's `allowed_fp` names the personas it may hurt: empty here,
so a Round 2 or Round 3 left unfixed FAILS on purpose.
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import personas_ch8  # noqa: E402,F401  (registers the `signup` scenario and the relabelled shoppers)
from checkpoint_core import Round, main, run_attack  # noqa: E402
from labclient import admin  # noqa: E402


# --- What the store really did, from the decision log --------------------------------------------------

def rows(actor):
    return admin("GET", "/lab/decisions", params={"actor": actor, "limit": 5000})["items"]


def accounts_created(decisions):
    """Signups that made a real, active account (a quarantined or faked one does not count)."""
    return sum(1 for d in decisions if d["method"] == "POST" and d["path"] == "/register"
               and d["extra"].get("account") == "created")


def reviews_published(decisions):
    return sum(1 for d in decisions if d["path"].startswith("/review/") and d["extra"].get("review") == "published")


def hits(decisions, layer):
    """Requests the store flagged with a signal from this check (form_traps, crawl_traps, responses)."""
    return sum(1 for d in decisions if f"{layer}:" in (d.get("signals") or ""))


def truth(script, actor, count):
    """Run an attack script, then replace its `succeeded` (what the bot believes) with the store's count."""
    def run():
        out = run_attack(script)
        decisions = rows(actor)
        out.update(believed=out["succeeded"], succeeded=count(decisions),
                   deceived=sum(1 for d in decisions if d["outcome"] == "deceived"),
                   quarantined=sum(1 for d in decisions if d["extra"].get("account") == "quarantined"))
        return out
    return run


def watched(script, actor):
    """Run a crawler script, then add what the traps saw of it: requests flagged by a crawl trap, by kind."""
    def run():
        out = run_attack(script)
        flagged = [d for d in rows(actor) if "crawl_traps:" in (d.get("signals") or "")]
        out["trap_hits"] = len(flagged)
        out["traps"] = sorted({s.split(":")[1] for d in flagged for s in d["signals"].split(",") if s.startswith("crawl_traps:")})
        return out
    return run


RECON = truth("attacks/round0_recon.py", "bot:r0_recon", accounts_created)
SPAMMER = truth("attacks/round1_form_spammer.py", "bot:r1_spammer", accounts_created)
MARKUP = truth("attacks/round1b_markup_aware.py", "bot:r1b_markup_aware", accounts_created)
PLAYWRIGHT = truth("attacks/round2_playwright_form.py", "bot:r2_playwright", accounts_created)
VERIFY = truth("attacks/round4_verify_signup.py", "bot:r4_verify", reviews_published)
CRAWLER = watched("attacks/round3_crawler.py", "bot:r3_crawler")
POLITE = watched("attacks/round3b_polite_crawler.py", "bot:r3b_polite_crawler")


# --- Checks beyond expect ------------------------------------------------------------------------------

def spammer_fooled(board, results, attacks):
    """Round 1's lesson: the bot reports success on every signup the store dropped."""
    a = attacks["spammer"]
    return a["believed"] == a["attempted"] and a["succeeded"] == 0 and a["deceived"] >= a["attempted"], (
        f"expected the spammer to believe {a['attempted']}/{a['attempted']} while the store created 0 "
        f"and answered {a['attempted']} with a fake success; believed {a['believed']}, created {a['succeeded']}, "
        f"deceived {a['deceived']}")


def crawler_trapped(board, results, attacks):
    """Round 3's lesson: all three crawl traps fire, and the crawler still gets the catalog (plus a canary)."""
    seen = {t: sum(1 for d in rows("bot:r3_crawler") if f"crawl_traps:{t}" in (d.get("signals") or ""))
            for t in ("trap_link", "honey_record", "decoy_endpoint")}
    canary = "p121" in attacks["crawler"].get("unlisted", [])
    return all(seen.values()) and canary, f"expected every crawl trap to fire and the honey SKU to be scraped: {seen}, honey={canary}"


def polite_clean(board, results, attacks):
    n = hits(rows("bot:r3b_polite_crawler"), "crawl_traps")
    return n == 0, f"the polite crawler should never touch a trap, but {n} requests were flagged"


def final_config(board, results, attacks):
    """Round 4's checkpoint is the recommended configuration; the four-way comparison is tools/round4_probe.py."""
    cfg = admin("GET", "/lab/traps")
    ok = (cfg["response_mode"], cfg["sanction_key"]) == ("quarantine", "session")
    return ok, (f"this checkpoint expects TRAP_RESPONSE_MODE='quarantine' and TRAP_SANCTION_KEY='session' in "
                f"defenses/policy.py; the store runs {cfg['response_mode']!r} / {cfg['sanction_key']!r}")


def verify_fooled(board, results, attacks):
    c = attacks["verify"]["conclusions"]
    return c == {"success": attacks["verify"]["attempted"]}, f"expected the verifying bot to conclude success every time, got {c}"


def spammers_contained(board, results, attacks):
    """Quarantine accepts the signup and parks it: trapped bots are still trapped, with the account quarantined."""
    n = sum(1 for d in rows("bot:r1_spammer") if d["extra"].get("account") == "quarantined")
    return n == attacks["spammer"]["attempted"], f"expected {attacks['spammer']['attempted']} quarantined signups from the spammer, saw {n}"


SOL = ("defenses/ladder.py",)
FORMS_L1 = {"recon": RECON, "spammer": SPAMMER, "markup": MARKUP}
EXPECT_L1 = {"recon": "blocked", "spammer": "blocked", "markup": "full"}
FORMS_L2 = {**FORMS_L1, "playwright": PLAYWRIGHT}
EXPECT_L2 = {"recon": "blocked", "spammer": "blocked", "markup": "blocked", "playwright": "full"}
CRAWL = {"crawler": CRAWLER, "polite": POLITE}

ROUNDS = {
    0: Round(level=0, description="recon against the open store", scenario="signup",
             attacks={"recon": RECON}, expect={"recon": "full"}),
    1: Round(level=1, description="a naive spammer vs the textbook honeypot", scenario="signup",
             attacks=FORMS_L1, expect=EXPECT_L1, extra_checks=[spammer_fooled],
             solutions=SOL + ("defenses/form_traps.py",)),
    2: Round(level=2, description="a rendering browser vs a CSS honeypot and a timing token", scenario="signup",
             attacks=FORMS_L2, expect=EXPECT_L2, extra_checks=[spammer_fooled],
             solutions=SOL + ("defenses/form_traps.py",)),
    3: Round(level=3, description="a polite crawler vs crawl traps and robots.txt", scenario="signup",
             attacks={**FORMS_L2, **CRAWL}, expect={**EXPECT_L2, "crawler": "full", "polite": "full"},
             extra_checks=[spammer_fooled, crawler_trapped, polite_clean],
             solutions=SOL + ("defenses/crawl_traps.py",)),
    4: Round(level=4, description="a bot that checks its work vs quarantine keyed on the session", scenario="signup",
             attacks={**FORMS_L2, **CRAWL, "verify": VERIFY},
             expect={**EXPECT_L2, "crawler": "full", "polite": "full", "verify": "blocked"},
             extra_checks=[final_config, spammers_contained, crawler_trapped, polite_clean, verify_fooled],
             solutions=SOL + ("defenses/responses.py", "defenses/policy.py")),
}

if __name__ == "__main__":
    main(ROUNDS)
