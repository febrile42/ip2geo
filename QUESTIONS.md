# Open Questions for Review

Design and product decisions that need your input before they're finalized.
Last updated: 2026-03-29.

---

## 1. Shell script content: paid vs. free

**Current state:**
- Free page (index.php): shows firewall rules inline for all *currently-visible* IPs (filtered by country/category UI). Rules update live as the user changes filters. Includes iptables, ufw, and nginx formats.
- Paid scripts (report.php): download `.sh` files for all scanning+VPN IPs from the original submission (now fixed to use all of them, not just top-25). iptables and ufw only. No nginx.

**The tension:** The free page output is arguably more flexible — the user can filter by category before generating rules. The paid scripts are static and fire-and-forget. You could argue the paid product is *less* configurable than the free page right now.

**Questions:**
- Should the paid scripts include cloud IPs in addition to scanning+VPN? Cloud egress IPs are suspicious in incident-response context, but blocking them can break legitimate SaaS traffic.
- Should the paid page add an nginx format? (Trivially easy to add; question is whether it belongs here.)
- Is the free page's live-filter-then-copy approach intentionally better, or is that an accident of implementation? Is the paid page supposed to be a polished static export, or a superset of free?
- Cap consideration: a 10,000-IP batch with 80% scanning/VPN produces ~8,000-line block scripts. Is there a reasonable cap (e.g., top 1,000 by freq)?

---

## 2. Frequency data: public page vs. paid report

**Current state:** IP frequency (how many times an IP appeared in the submitted text) is stored in `ip_list_json` and used to rank the paid threat report's top-25. It is **not** shown on the free public page.

**Decision made (2026-03-25):** Keep freq silent on the free page for now; use it only in the paid report.

**Question to revisit:** Should freq ever surface on the free page? Options:
- Show freq as a column in the public results table.
- Show a "top repeat offenders" callout above the table.
- Leave it paid-only as a differentiator.

---

## 3. "View all IPs" page performance

**Current state:** `/?view_token=TOKEN` re-runs the full geo lookup loop against the DB for every IP in the original submission. This is the same query path as a fresh POST and can take 2-4s for 10,000-IP batches.

**Question:** Should we cache the full geo results in the report row (a `geo_results_json` column), or is the re-query cost acceptable? Trade-off is DB column size (potentially large) vs. latency on the view page.

---

## 4. Country filter on "View all IPs" page

**Current state:** view_token mode shows all IPs with no country filtering. The standard filter UI (category chips, country chips) is still shown, so users can filter client-side after load.

**Question:** Should the view_token page pre-apply the same country filter that was used in the original lookup? (We don't currently store what the original filter was.) Or is "show all, filter client-side" the right default?

---

## 5. Report expiry + re-access model

**Current:** Reports expire after 30 days. The `view_token` link (`/?view_token=TOKEN`) also expires after 30 days because it reads from the same `reports` table (status must be paid/redeemed).

**Question:** Is 30 days the right window? Should "View all IPs" have a different expiry than the report itself? (Currently they're tied to the same token.)
