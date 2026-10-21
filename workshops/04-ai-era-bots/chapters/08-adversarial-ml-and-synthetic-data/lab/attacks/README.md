# attacks/

Empty in the starter. A chapter lab adds one script per attack step, `roundN_<name>.py`.

Every attack script:

```python
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
from labclient import LabClient, world_pool, form_fields, csrf_of   # guarded by ../labnet.py

bot = LabClient("bot:round1", pool=world_pool("cloud_vm"))          # rent addresses, label yourself
r = bot.get("/api/products", headers=[("User-Agent", "python-requests/2.34.2")])
print(bot.verdict())                                                 # (verdict, score, signals)
```

Rules of engagement, enforced in code: `labclient` imports the `labnet` guard, which refuses any
`DEMO_URL` that is not this machine, and the lab edge refuses any source address outside `data/world.json`. Lab traffic never
leaves localhost; no public proxy, VPN or Tor node is ever contacted. Only synthetic users,
credentials and data (`demo_site/seed.py`).

The DOM and API contract an attack may rely on is in `workshops/STORE_CONTRACT.md`. End a script
by printing one JSON line (`{"requests": 120, "bought": 3}`) so `tools/checkpoint.py` can read it.
