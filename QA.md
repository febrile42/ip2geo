# ip2geo QA Guide

For use with the gstack `/qa` skill. Tests the live site as a user — no source code reading, no Stripe credentials needed.

## URLs

| | URL |
|---|---|
| **Staging base** | `https://staging.ip2geo.org` |
| **Production base** | `https://ip2geo.org` |
| **Demo report** | `https://staging.ip2geo.org/report.php?token=00000000-0000-0000-0000-000000000000` |
| **Demo view-all IPs** | `https://staging.ip2geo.org/?view_token=00000000-0000-0000-0000-000000000000` |
| **Demo token** | `00000000-0000-0000-0000-000000000000` |

## DO NOT TEST

- **Stripe payment flow** — clicking "Get Threat Report" leads to Stripe checkout; do not proceed
- **Token generation** — same as above; the CTA button is off-limits
- **Email delivery** — do not submit a real email address on send-report-link.php
- **Webhook handler** — internal POST endpoint, not browser-testable
- **Umami analytics** — only fires on ip2geo.org (not staging); event tracking cannot be verified on staging

---

## 1. Smoke checks

Load each URL and verify HTTP 200, no error page, correct page title:

- `https://staging.ip2geo.org/` — "Bulk IP Lookup & Location Finder"
- `https://staging.ip2geo.org/report.php?token=00000000-0000-0000-0000-000000000000` — "Threat Report"
- `https://staging.ip2geo.org/?view_token=00000000-0000-0000-0000-000000000000` — main page with results
- `https://staging.ip2geo.org/send-report-link.php?token=00000000-0000-0000-0000-000000000000` — "Resend Report Link"
- `https://staging.ip2geo.org/changelog.php` — "ip2geo.org Changelog"
- `https://staging.ip2geo.org/privacy.php` — "ip2geo.org Privacy Policy"
- `https://staging.ip2geo.org/legal.php` — "ip2geo.org Legal & Refund Policy"

---

## 2. Main page (index.php)

### Form submission

Submit this IP list in the textarea:

```
1.1.1.1
8.8.8.8
45.83.64.1
194.165.16.72
```

Expected:
- Loading overlay appears ("Processing N IPs...") while request is in flight
- Results table appears with columns: IP, Country, State/Province, City, ASN, ASN Org, Category
- Summary stats below table show submitted / matched / unresolved counts
- Page scrolls to results automatically

### Threat CTA (do not click the pay button)

Submit this IP list (known Tor exit nodes — should trigger HIGH verdict CTA):

```
185.220.101.1
185.220.101.2
185.220.101.3
185.220.101.4
185.220.101.5
185.220.101.6
185.220.101.7
185.220.101.8
```

Expected:
- Verdict badge appears above results (HIGH/MODERATE/LOW with matching background color)
- "Get Threat Report + Block Scripts — $9" button is visible
- **STOP** — do not click the button

### Category and country filters

After the IP lookup above, verify:
- Category chips appear in the filter section: Scanning, VPN/Proxy (at minimum for this batch)
- Clicking a chip hides matching rows; clicking again restores them
- Country chips appear; clicking one limits visible rows to that country
- Shift-click should select multiple countries
- Row count in summary updates as filters change

### CSV download

- Click "Download CSV" — file should download without page reload
- CSV should contain only currently visible (non-hidden) rows (test by filtering first, then downloading)

### Firewall rule previews

- Click "iptables" button — code block appears with `iptables -A INPUT -s {ip} -j DROP` lines
- Click "ufw" button — code block with `ufw deny from {ip}` lines
- Click "nginx" button — code block with nginx geo config format
- Each block has a "Copy" button
- Button label changes from "Show" to "Hide" on reveal, and back on second click

### "See a sample report" link

- Verify the link is visible on the page
- Verify it navigates to the demo report URL (`/report.php?token=00000000-0000-0000-0000-000000000000`)

### Cancelled flow

Visit `https://staging.ip2geo.org/?cancelled=1`
- Page loads normally with the lookup form
- No error message shown

---

## 3. Demo report (report.php)

Visit: `https://staging.ip2geo.org/report.php?token=00000000-0000-0000-0000-000000000000`

### Page structure (verify top to bottom)

1. **Demo banner** — text includes "Demo Report" and references Tor exit nodes
2. **Verdict badge** — HIGH verdict, red/pink background color
3. **Verdict text** — threat narrative paragraph present
4. **AbuseIPDB callout** — references number of verified IPs
5. **Next Steps** — ordered list with 3 items
6. **ASN Ranges section** — CIDR chips visible, ASN org names labeled
7. **Block Rules column** — two tabs present: "Block by Range" (active by default) and "Block by IP"
8. **Top Threat Sources table** — top-25 IPs with Hits column and AbuseIPDB score column
9. **Footer links** — "Copy report link", "View all IPs", expiry date visible

### Block Rules tabs

- "Block by Range" tab is active by default — verify download links present: iptables-ranges, ufw-ranges, nginx-ranges, plain text (.txt)
- Click "Block by IP" tab — verfy it activates (underline indicator moves), shows iptables, ufw, nginx download links
- Tab switch: no page reload, smooth

### Block script filter

- Expand the collapsible filter section (click the `<details>` summary)
- Verify Scanning and VPN/Proxy category checkboxes are present
- Verify country chips appear (demo report has many countries)
- Deselect a country chip — the blockable IP counter should update

### Script download (spot-check one)

- Click the "iptables" download link in the "Block by IP" tab
- File should download (`.sh` extension)
- Open/inspect the file: first line must be `#!/bin/bash`
- A comment line should include IP count and generation date
- Body: one `iptables -A INPUT -s {ip} -j DROP` per line
- Several IPs in the 185.220.x.x range should be present (Tor exits)

### Report link copy

- Find the copyable report URL near the bottom of the page
- Click it — text should auto-select
- Verify button label changes to "Copied!"

### "View all IPs" link

- Click it — navigates to `/?view_token=00000000-0000-0000-0000-000000000000`
- Page scrolls to results table automatically

### "Print / Save as PDF" button

- Button is visible in the report header
- Clicking it triggers the browser's print dialog (do not actually print — just verify the dialog opens)

---

## 4. Community Consent Flow (on report page)

**Test via demo report:** The demo token (`00000000-0000-0000-0000-000000000000`) has `data_consent` hardcoded to show the banner. In actual testing, use a real paid report token where `data_consent IS NULL` — the banner only appears for that state.

**Consent banner (data_consent IS NULL):**
- The banner should appear near the top of a paid report page for a new report
- Banner heading: "Community Intel — opt in" (or similar)
- Banner has two buttons: opt-in and decline
- Demo report will NOT show the banner (demo has consent pre-set); this flow requires a real paid report token

**AJAX opt-in flow:**
- POST to `/community-consent.php` with `token` and `consent=1`
- On success: banner replaces itself with a community callout (no page reload)
- Response includes `ok: true, ingested: true, week_start: ..., top_cidrs: [...]`

**AJAX decline flow:**
- POST to `/community-consent.php` with `token` and `consent=0`
- On success: banner disappears, `data_consent=0` set in DB
- Idempotent: visiting the report again should NOT show the banner

**Community column in top-25 table (data_consent = 1):**
- When opted in, a "Community" column appears after the AbuseIPDB column
- Column shows e.g. "31 servers ↑" or "—" for IPs with <3 reports
- IPs with 3-19 community reports show "(beta)" badge
- IPs with 20+ reports show without qualifier
- Column NOT present in DOM when data_consent != 1

**Direct endpoint tests (can be tested with curl or browser network tab):**
- POST to `/community-consent.php` with missing token: HTTP 400, `{"error":"bad_request"}`
- POST with invalid token: HTTP 400, `{"error":"invalid_token"}`
- GET request (not POST): HTTP 405, `{"error":"method_not_allowed"}`

---

## 5. /intel.php — Public Community Block List

**Page load:**
- Visit `https://staging.ip2geo.org/intel.php`
- If < 5 opted-in reports exist for the current week: page shows "Not enough data yet this week — check back soon." message
- If >= 5 reports: page shows the block list table

**Content (when data is present):**
- Header: "Community Block List — Week of {date}"
- Subhead mentions N opted-in ip2geo reports
- Ranked CIDR table with columns: CIDR, ASN Org, Reports (this week), Hits (this week)
- 4 download buttons: iptables, ufw, nginx, plain .txt — each triggers a file download
- CTA links at bottom: "See a sample report" and "Analyze your own logs"

**Download files (if data exists):**
- Click iptables download: file should start with `#!/bin/bash` comment header
- Click plain .txt download: one CIDR per line, no shell commands

**Known limitation:**
- Without enough opted-in real reports, the data threshold page will be shown. QA agent cannot submit real reports to populate this. Test the empty-state page, confirm no 500 errors.

---

## 6. View-all page (?view_token=)

Visit: `https://staging.ip2geo.org/?view_token=00000000-0000-0000-0000-000000000000`

- Page should load quickly (results served from cache, no re-query delay)
- Full IP table visible with all columns
- Category and country filter chips are present and functional
- "← Back to your report" link visible, links back to `/report.php?token=00000000-0000-0000-0000-000000000000`
- CSV download works; verify it respects active filters (apply a filter first, then download)

---

## 7. Resend report link page (send-report-link.php)

Visit: `https://staging.ip2geo.org/send-report-link.php?token=00000000-0000-0000-0000-000000000000`

- Page loads (not 500)
- Email input form is visible (demo token has no stored email on file)
- Expiry date shown in the form text

**Validation — test these, do NOT submit a real email:**

| Input | Expected error |
|---|---|
| (blank, submit) | "Please enter an email address." |
| `notanemail` | "That does not look like a valid email address." |

**Invalid token:**

Visit `https://staging.ip2geo.org/send-report-link.php?token=bad-token`
- Error message: "This report link is invalid or has expired."

---

## 8. Static pages

For each page: loads cleanly, no broken layout, correct content present.

### changelog.php

- Most recent version listed: **3.0.0** (with date 2026-04-02 or similar)
- Version history goes back to at least 2.0.7
- Header nav: "ip2geo.org" title links to home, "Home" nav link present

### privacy.php

- "Threat Reports" section present (covers 30-day data retention)
- Stripe mentioned as payment processor with link to their privacy policy
- AbuseIPDB mentioned as third-party lookup service
- `support@ip2geo.org` contact link present

### legal.php

- Three policy sections present: **Refund Policy**, **Cancellation Policy**, **Dispute Policy**
- Refund policy states "all sales are final" with 7-day exception for technical failures
- `support@ip2geo.org` contact link present in multiple sections

### Footer (verify on all pages)

- "Privacy Policy" link → `/privacy.php`
- "Refund Policy" link → `/legal.php`
- `support@ip2geo.org` mailto link

---

## 9. Scroll behavior

- **Form submit on index.php:** after results load, page should be scrolled to the results section (not stuck at top)
- **view_token page load:** `/?view_token=...` should scroll to the results table on load

---

## Known issues / skip list

- No admin panel exists
- `webhook.php` is an internal POST-only endpoint — not browser-testable
- `get-report.php` is POST-only and redirects to Stripe — not browser-testable
- AbuseIPDB scores on the demo report may be 0 if the staging cache is cold (not a bug)
- Staging deploy can lag ~2 minutes behind the latest push to develop
