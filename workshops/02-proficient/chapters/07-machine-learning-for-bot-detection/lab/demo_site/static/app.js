// Placeholder for the page collector.
// In W2 Ch3 (behavior) and W2 Ch4 (fingerprinting) this script gathers mouse,
// keyboard and touch statistics plus a device fingerprint, then POSTs two
// summaries to /api/telemetry:
//   {"kind": "fp",  "data": {platform, ua, gpu, screen, dpr, tz, langs, hw, touch, webdriver, canvas}}
//   {"kind": "beh", "data": {mouse_moves, straightness, speed_cv, clicks, keys, key_cv,
//                            touches, scrolls, first_input_ms}}
// The lab's simulators send those summaries directly (tools/shopper.py), so
// no browser is needed. Everything the client sends is attacker-controlled.
