"""
Product images: a deterministic SVG per SKU, generated on request (no binaries
in the repo). The category picks the silhouette, the SKU hash picks the
palette. Realistic enough that a page looks like a shop, and every image is a
cacheable static asset a crawler will fetch (W4 Ch1 cares about that).
"""

import hashlib

PALETTES = [
    ("#1f2937", "#f59e0b", "#fde68a"), ("#0f766e", "#99f6e4", "#134e4a"), ("#7c2d12", "#fb923c", "#fed7aa"),
    ("#1e3a8a", "#93c5fd", "#dbeafe"), ("#3f3f46", "#a1a1aa", "#e4e4e7"), ("#4c1d95", "#c4b5fd", "#ede9fe"),
    ("#14532d", "#86efac", "#dcfce7"), ("#831843", "#f9a8d4", "#fce7f3"),
]

SHAPES = {
    "shoes": '<path d="M40 150c0-20 30-40 60-45l30-25c10-8 25-6 35 5l55 45c30 15 60 20 100 25 10 2 10 20 0 22H60c-12 0-20-10-20-27z"/>'
             '<path d="M120 110l20-18M140 118l20-18M160 126l20-18" stroke-width="6" stroke-linecap="round" fill="none"/>',
    "packs": '<rect x="100" y="60" width="120" height="150" rx="30"/><rect x="120" y="140" width="80" height="50" rx="12" fill-opacity=".35"/>'
             '<path d="M120 60c0-25 80-25 80 0" stroke-width="10" fill="none" stroke-linecap="round"/>',
    "jackets": '<path d="M110 60l50-20 50 20 50 30-20 50-25-10v110H105V130l-25 10-20-50z"/>'
               '<path d="M160 40v170" stroke-width="6" stroke-opacity=".5"/>',
    "headlamps": '<rect x="70" y="110" width="180" height="40" rx="20" fill-opacity=".5"/><rect x="110" y="80" width="100" height="90" rx="18"/>'
                 '<circle cx="160" cy="125" r="28" fill-opacity=".9"/><circle cx="160" cy="125" r="14"/>',
    "poles": '<path d="M130 30l20 200M190 30l20 200" stroke-width="10" stroke-linecap="round"/>'
             '<rect x="118" y="20" width="26" height="60" rx="10"/><rect x="178" y="20" width="26" height="60" rx="10"/>'
             '<circle cx="150" cy="200" r="16" fill-opacity=".6"/><circle cx="210" cy="200" r="16" fill-opacity=".6"/>',
    "kitchen": '<path d="M90 90h140l-15 120H105z"/><rect x="80" y="70" width="160" height="22" rx="8"/>'
               '<path d="M230 110h30c15 0 15 50 0 50h-25" stroke-width="10" fill="none" stroke-linecap="round"/>',
}


def palette_for(sku):
    h = int(hashlib.sha256(sku.encode()).hexdigest()[:8], 16)
    return PALETTES[h % len(PALETTES)]


def svg(sku, category, name="", width=320):
    bg, fg, accent = palette_for(sku)
    shape = SHAPES.get(category, SHAPES["kitchen"])
    label = (name or sku)[:28]
    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 320 320" width="{width}" height="{width}" role="img" aria-label="{label}">
<defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="{accent}"/><stop offset="1" stop-color="{bg}" stop-opacity=".25"/></linearGradient></defs>
<rect width="320" height="320" rx="24" fill="url(#g)"/>
<rect x="18" y="18" width="284" height="284" rx="18" fill="{bg}" fill-opacity=".06"/>
<g fill="{fg}" stroke="{bg}" stroke-width="4" transform="translate(0 20)">{shape}</g>
<text x="160" y="292" text-anchor="middle" font-family="system-ui, sans-serif" font-size="16" font-weight="600" fill="{bg}">{label}</text>
</svg>"""
