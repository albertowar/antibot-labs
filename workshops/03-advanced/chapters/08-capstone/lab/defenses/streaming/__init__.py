"""Capstone L6 — real-time streaming detection (W3 Ch3).

The browser layers score one action at a time, at the moment it happens. A
streaming layer scores the *stream*: it sees every request as it arrives and
keeps per-session state (a sliding rate window, an online variance estimate, a
navigation tally). That is what closes the latency gap — a burst that a
session-level scorer meets only at checkout has already moved the streaming
counters by the time the buy arrives.

Default (STREAM_BACKEND=inproc): events are processed inline in the Flask
process, so state is always current and the lab is deterministic. Optional
(STREAM_BACKEND=kafka): the same observe() runs in a consumer against a real
Redpanda topic — see bus.py and docker-compose's `prod` profile.
"""
