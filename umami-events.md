# Umami Analytics Events

Quick reference for every custom event we fire. Umami shows these under
"Events" in the dashboard. Pageviews are automatic — only the custom events
below need explanation.

---

## Home page (index.php)

### `lookup_submit`
Someone hit the Submit button and got results. Includes a bucket for how many
IPs they pasted in (`1-10`, `11-50`, `51-200`, `201-1000`, `1001-5000`, `5000+`).
This is the core usage metric — how often is the tool actually being used and
at what scale.

### `download_csv`
Someone downloaded the results table as a CSV from the home page. Signals a
power user who wants the data for their own processing.

---

## Report page (report.php)

### `report_purchase`
Fires **once** on the very first load after a successful Stripe checkout —
when the token transitions from `paid` → `redeemed` and the report is generated
for the first time. Never fires on return visits or demo reports.

Fields:
- `revenue` — `9.00` (USD)
- `currency` — `"USD"`
- `verdict` — the threat verdict (e.g. `"high"`, `"moderate"`, `"low"`, `"minimal"`)
- `ip_count_bucket` — same buckets as `lookup_submit`

This is the primary revenue signal. Compare it against `cta_click` to see the
full funnel: click → Stripe cancel → purchase.

### `report_view`
Fires once when the report page fully loads and renders. Carries three fields:
- `is_demo` — true if it's the demo report, false if it's a real paid report
- `verdict` — the threat verdict shown (e.g. `"high"`, `"moderate"`, `"low"`, `"minimal"`)
- `ip_count_bucket` — same buckets as lookup_submit above

This is how we tell real report views apart from demo views, and how we see
what verdict mix users are actually encountering.

### `report_download`
Someone downloaded a firewall block list from their report. Two fields:
- `format` — `iptables`, `ufw`, `nginx`, or `cidr` (the plain text list)
- `scope` — `by-ip` (the per-IP download) or `by-range` (the CIDR/ASN range download)

High download rate on a report = user found the report actionable and took it
somewhere.

### `report_tab_switch`
Someone clicked one of the tabs on the report (Summary, Top IPs, By Range, etc.).
The `tab` field has the tab name. Tells us which sections people actually look at
beyond the default view.

### `report_copy_link`
Someone clicked the "Copy link" button to share their report URL. Useful for
seeing whether paid reports are being shared.

### `report_view_all_ips`
Someone clicked through to view the full expanded IP list (the "view all" link
that appears when there are more IPs than the default display cap). Signals they
dug into the detail, not just skimmed the summary.

---

## Report page — firewall rules panel (ip2geo-app.js)

### `show_rules_<block>`
Someone expanded the firewall rules panel for a specific block. The suffix is the
block name, e.g. `show_rules_iptables`, `show_rules_ufw`, `show_rules_nginx`.
Fires when they open the panel — not when they copy.

### `copy_rules_<block>`
Someone clicked "Copy" on a firewall rules block. Same suffix convention as above.
This is the stronger signal — they actually grabbed the rules to use somewhere.

---

## Report page — filters (ip2geo-app.js)

### `filter_country`
Someone used the country filter on their report. The `country` field is the
two-letter country code they selected. Shows which countries users are drilling
into most.

### `filter_category`
Someone toggled one of the category checkboxes (Scanning, VPN/Proxy, Cloud,
Residential, etc.). Fields: `category` (the category name) and `checked`
(true = turned on, false = turned off).

---

## Checkout / payment (ip2geo-app.js)

### `cta_click`
Someone clicked the main "Get Report" / upgrade CTA button. Fires on click,
before Stripe loads. Useful for comparing CTA clicks vs actual completed
purchases (the gap = Stripe drop-off).

### `stripe_cancel`
Someone came back to the page with `?cancelled=1` in the URL — i.e. they opened
the Stripe checkout and then clicked the back/cancel button without paying.
We strip the query param immediately after firing so it doesn't persist in
browser history.
