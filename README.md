# Site Inspector - Trust & Safety

A browser extension for Firefox and Chrome that gives the website you're on a trust score from 1 to 10.

## What it checks

When you click the toolbar icon, the popup runs these checks in parallel:

| Check | Source | Points |
|---|---|---|
| Protocol | HTTPS vs plain HTTP | 2 |
| Domain age | Registry lookup (RDAP), falling back to Wayback Machine history | 2 |
| First seen online | Earliest Wayback Machine capture | 2 |
| Hosting | IP lookup (Google DNS) and provider lookup (ipapi.co) | 2 |
| Reputation | Tranco traffic rank and Quad9 threat blocklist | 2 |

It also shows whether the site sends HSTS, CSP, and X-Frame-Options security headers.

If a site is on a threat blocklist, the score is capped at 2. Results are cached for an hour in the browser's session storage. See `report.html` for the full scoring guide.

The score is an automated estimate, not a guarantee of safety.

## Install for testing

**Firefox:** open `about:debugging` → This Firefox → Load Temporary Add-on, and pick `manifest.json`.

**Chrome:** open `chrome://extensions`, turn on Developer mode, click Load unpacked, and pick this folder.

## Build store packages

```bash
python3 build.py
```

This writes `dist/site-inspector-firefox.zip` and `dist/site-inspector-chrome.zip`, with `manifest.json` at the top of each ZIP. The Chrome build leaves out the Firefox-only manifest settings.

## Privacy

The extension has no server of its own and does no tracking. When you open the popup, the current site's domain is sent to the public lookup services above. See [PRIVACY.md](PRIVACY.md).
