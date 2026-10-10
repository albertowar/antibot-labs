"""Lab-only password hashing cost (shared helper).

Production password hashing is deliberately expensive — hundreds of thousands of
PBKDF2 iterations, or a memory-hard function — so a single login costs ~100 ms.
That cost is itself a defender expense under stuffing (every guess burns it), a
point the chapter makes on a slide. But at production cost, a 2000-pair attack
round would take minutes, so the lab turns the iteration count way down. Never
ship this value: it exists only to keep the exercise responsive.

``check_password_hash`` reads the method and iteration count back out of the stored
hash, so as long as everything is created with this helper the verification cost
matches and the timing-oracle demo (L3) stays honest.
"""

from werkzeug.security import generate_password_hash

LAB_HASH_METHOD = "pbkdf2:sha256:1000"   # lab-only; production is ~600k


def hash_pw(password: str) -> str:
    return generate_password_hash(password, method=LAB_HASH_METHOD)
