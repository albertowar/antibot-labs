"""
How the agent reads a page.

A browser agent does not parse HTML the way a scraper does. It builds a list
of things it can act on — their role, their accessible name, their value —
much like the accessibility tree a screen reader uses. browser-use, Playwright
MCP and Chrome DevTools MCP all do a version of this. We collect:

    url, title, visible text (truncated)
    elements: [{index, tag, role, name, selector, value}]
    last_result: the text of #result, so the agent sees what its last action did

snapshot() can also draw numbered highlight boxes over each element. Some agent
tools do this so a vision model can refer to "element 7". It is injected DOM,
and collector.js reports it (Round 2). highlight=False is the default; the
Round 2 attack turns it off to stay quiet, which is the point of that round.
"""

EXTRACT_JS = r"""
(drawHighlights) => {
  const sel = 'a, button, input, select, textarea, [role=button], [role=link]';
  const out = [];
  let box = document.getElementById('lab-agent-highlights');
  if (drawHighlights && !box) {
    box = document.createElement('div');
    box.id = 'lab-agent-highlights';
    box.style.cssText = 'position:fixed;inset:0;pointer-events:none;z-index:2147483647';
    document.body.appendChild(box);
  }
  document.querySelectorAll(sel).forEach((el, i) => {
    const r = el.getBoundingClientRect();
    if (r.width === 0 || r.height === 0) return;
    const name = (el.getAttribute('aria-label') || el.innerText || el.value ||
                  el.placeholder || el.name || '').trim().slice(0, 80);
    let selector = el.id ? '#' + CSS.escape(el.id)
                 : el.name ? el.tagName.toLowerCase() + '[name=' + CSS.escape(el.name) + ']'
                 : el.tagName.toLowerCase();
    out.push({index: i, tag: el.tagName.toLowerCase(),
              role: el.getAttribute('role') || el.type || el.tagName.toLowerCase(),
              name, selector});
    if (drawHighlights && box) {
      const h = document.createElement('div');
      h.className = 'lab-agent-highlight';
      h.style.cssText = 'position:absolute;border:2px solid #e11;pointer-events:none;' +
        'left:' + (r.left) + 'px;top:' + (r.top) + 'px;width:' + r.width + 'px;height:' + r.height + 'px';
      h.textContent = i;
      box.appendChild(h);
    }
  });
  return {url: location.href, title: document.title,
          text: (document.body.innerText || '').slice(0, 1500), elements: out};
}
"""


def snapshot(page, highlight=False):
    snap = page.evaluate(EXTRACT_JS, highlight)
    try:
        el = page.query_selector("#result[data-outcome]")
        if el:
            snap["last_result"] = {"outcome": el.get_attribute("data-outcome"),
                                   "text": (el.inner_text() or "")[:300]}
    except Exception:
        pass
    return snap


def find(snapshot_dict, **by):
    """First element whose fields match (case-insensitive substring on name/role/tag)."""
    for el in snapshot_dict.get("elements", []):
        if all(str(by[k]).lower() in str(el.get(k, "")).lower() for k in by):
            return el
    return None
