# Umami Analytics Events

Quick reference for every custom event we fire. Umami shows these under
"Events" in the dashboard. Pageviews are automatic — only the custom events
below need explanation.

**v5 update:** Threat Reports were retired completely (R17) — `report.php`
now returns HTTP 410 for every token. Every event that only ever fired from
that page (`report_purchase`, `report_view`, `report_download`,
`report_tab_switch`, `report_copy_link`, `report_view_all_ips`) and the
Stripe checkout events (`cta_click`, `stripe_cancel`) no longer fire and are
removed from this doc. The firewall-rules and filter events below now apply
only to the home page — they used to fire from `report.php` too, but that
page has nothing left to click.

---

## Home page (index.php)

### `lookup_submit`
Someone hit the Submit button and got results. In v5 this fires from the
workbench (`assets/js/workbench.js`) once the lookup returns; it also fires
the `ip2geo:lookup_submit` DOM event that Recent lookups listens for. Fields:
- `ip_count_bucket` — how many unique IPs they pasted in (`1`, `2-10`,
  `11-50`, `51-100`, `101-500`, `501-1000`, `1001-5000`, `5000+`)
- `sample` — `true` when the lookup came from "Try a sample log" without the
  visitor editing the textarea afterward, `false` otherwise (D11/R13)

This is the core usage metric — how often is the tool actually being used and
at what scale. `verdict_level` and `cta_shown` no longer appear: v5 has no
CTA or verdict to report (R17).

### `download_csv`
Someone downloaded the results table as a CSV from the no-JS results page. Signals a
power user who wants the data for their own processing.

---

## Home page: workbench (workbench.js, v5)

### `copy_export_<format>`
Someone copied the current filtered rows in an export format. The suffix is
the format key from `assets/js/export-templates.js`: `tsv`, `csv`, `kql`,
`spl`, `iptables`, `ufw`, `nginx`. No properties; nothing from the paste.

### `share_link_created`
Someone copied a `#v=` share link. No properties. The IPs live only in the URL
fragment, and the fragment is stripped before the tracker loads (R3), so
opening a shared link never sends its contents to analytics.

### `filter_category` / `filter_country` / `filter_search`
Someone used one of the workbench's own filter controls: the category chips,
the country chips, or the free-text search box. No properties (D9): only the
dimension that was touched is recorded, never the value — not the category
name, not the country code, and never the search text, since a visitor can
type an IP or hostname into search. `filter_search` is debounced 600ms after
the last keystroke so a single search doesn't spam events per character.

This replaced a v5 gap: the workbench's filter chips (`assets/js/filters.js`)
used to fire nothing, so filter usage went unmeasured once a browser-side
lookup swapped the server-rendered `#results` table for `#workbench-root`.
See `filter_category` / `filter_country` below for the older, still-present
handlers on the server-rendered table — those fire only for visitors who
never get a workbench (no-JS, or JS load failure), and their `filter_category`
carries different fields, so don't merge the two in a dashboard without
checking which section the row came from.

---

## Home page — firewall rules panel (ip2geo-app.js)

### `show_rules_<block>`
Someone expanded the firewall rules panel for a specific block. The suffix is the
block name, e.g. `show_rules_iptables`, `show_rules_ufw`, `show_rules_nginx`.
Fires when they open the panel — not when they copy.

### `copy_rules_<block>`
Someone clicked "Copy" on a firewall rules block. Same suffix convention as above.
This is the stronger signal — they actually grabbed the rules to use somewhere.

---

## Home page — filters, no-workbench fallback (ip2geo-app.js)

These two handlers bind to the server-rendered results table
(`#filter-countries`, `.filter-category`) inside `#results`. A visitor only
sees that table — and these events only fire — when the workbench never took
over: no JS, or the browser-side lookup in `assets/js/workbench.js` never
ran. Once a lookup succeeds client-side, `#results` stays hidden and
`#workbench-root` takes its place, so the same filter action instead fires
the `filter_category` / `filter_country` / `filter_search` events documented
above under workbench — note `filter_category` here still carries the
`category`/`checked` fields that the workbench version dropped for D9.

### `filter_country`
Someone used the country filter chips. No properties (R9/D8): the country
code the user would drill into comes from their own paste, so as of v5 we
only record that the filter was used, not which value. Still shows overall
filter-usage volume; the per-country breakdown chart in Umami stops here.

### `filter_category`
Someone toggled one of the category checkboxes (Scanning, VPN/Proxy, Cloud,
Residential, etc.). Fields: `category` (the category name — a fixed ip2geo
label, not paste data) and `checked` (true = turned on, false = turned off).

---

## Home page: Recent lookups (ip2geo-app.js)

Recent lookups is a list kept in the visitor's own browser (localStorage) so
they can re-run an earlier lookup. It is on by default. None of these events
carry properties, and none include anything from a lookup.

### `recent_lookups_use`
Someone clicked a saved lookup and it was restored into the paste box. This is
the only signal that the feature is actually used; the events below only show
people turning it on, off, or clearing it. Added in 4.3.3 so there is at least
30 days of data before deciding whether v5 keeps the feature.

### `recent_lookups_optin` / `recent_lookups_optout`
Someone turned the feature on, or off. Turning it off with saved entries also
clears them, with an Undo toast.

### `recent_lookups_clear`
Someone clicked Clear on the list.

### `recent_lookups_undo`
Someone clicked Undo on the toast after turning it off or clearing it.
