"""
login_stack: Chapter 5's finished login decision, wired at LADDER[0] so it runs at every level of this chapter.

Chapter 5's stepup_policy branches on the level: level 1 is its blanket emailed code, level 2 and up its
risk-scored login. This chapter's levels count its own rounds, so level 1 here must not mean "blanket code".
This wrapper runs stepup_policy as if the level were 2 or more, and changes nothing else. (Nothing in
Chapter 5's files is edited.)
"""

from . import stepup_policy
from .pipeline import Check


def _check(ctx):
    saved = ctx.level
    ctx.level = max(saved, 2)
    try:
        return stepup_policy._check(ctx)
    finally:
        ctx.level = saved


CHECK = Check("login_stack", _check, phases=("action:login_result",))
