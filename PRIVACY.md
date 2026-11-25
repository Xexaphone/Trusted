# Privacy Policy for Site Inspector - Trust & Safety

Last updated: 2026-11-21

Site Inspector is a browser extension for Firefox and Chrome that shows an automated trust score for the website you are viewing. This policy explains what data the extension handles and where it goes.

## Summary

- The extension does not collect, store, or sell personal data.
- The extension does not have accounts, analytics, advertising, or tracking.
- The extension has no server of its own. Nothing is sent to the developer.
- When you open the popup, the domain of the current site is sent to public lookup services to produce the score. Those services are listed below.

## Data the extension processes

When you click the extension icon on a standard web page (http or https), it uses:

- **The domain name of the current tab** (for example, `example.com`).
- **The full address of the current tab**, which is requested once from that same site to read its security headers.

This happens only when you open the popup. The extension does not run in the background and does not read pages you visit when the popup is closed.

## Third-party services

To calculate the score, the extension sends the domain (or the IP address of the site's server) to these public services:

| Service | Operator | What is sent | Purpose |
|---|---|---|---|
| rdap.org and rdap.iana.org | Registry lookup services | Domain name | Registration date and registrar |
| web.archive.org | Internet Archive (Wayback Machine) | Domain name | First-seen date |
| tranco-list.eu | Tranco project | Domain name | Traffic rank |
| dns.quad9.net | Quad9 | Domain name | Threat blocklist status |
| dns.google | Google | Domain name | IP address lookup |
| ipapi.co | ipapi | IP address of the site's server | Hosting location and provider |

These services receive the requests in the normal way web requests work, so they can see your IP address and that your browser asked about these domains. Please review their privacy policies for how they handle that data:

- Internet Archive: https://archive.org/about/terms.php
- Google: https://policies.google.com/privacy
- Quad9: https://quad9.net/privacy/policy/
- ipapi: https://ipapi.co/privacy/
- Tranco: https://tranco-list.eu/
- Registry lookup services (rdap.org, rdap.iana.org): operated by their respective registries

## Local storage

The extension keeps each result in your browser's session storage for one hour, or until you close the browser, whichever comes first. This data stays on your device. It is never sent anywhere and is not shared with the developer. You can clear it by restarting the browser.

## Links to other sites

The popup contains links to Trustpilot reviews and to a Buy Me a Coffee page. These open in a new tab only when you click them, and they are governed by those sites' own privacy policies.

## Children's privacy

The extension is not directed at children and does not knowingly collect information from anyone.

## Changes to this policy

If this policy changes, the new version will be published at the same location and the "Last updated" date will be revised.

## Contact

Questions about this policy can be sent to: [your contact email or GitHub issues link]
