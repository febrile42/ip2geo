# Open Questions for Review

Design and product decisions that need your input before they're finalized.
Last updated: 2026-04-02.

---

## 1. Shell script content: paid vs. free — RESOLVED 2026-04-02

Paid report now has category filters + Block by IP tab + Block by Range tab. No longer behind free. Closed.

---

## 2. Frequency data: public page vs. paid report — RESOLVED 2026-04-02

Freq stays paid-only. Intentional differentiator.

---

## 3. "View all IPs" page performance — RESOLVED 2026-04-02

Implemented `geo_results_json` column, stored at generation time, nulled after redemption to reclaim space. No re-query cost. (commits f5666a5, 57c7e84)

---

## 4. Country filter on "View all IPs" page — WONTDO

"Show all, filter client-side" is the right default. Not worth storing original filter state.

---

## 5. Report expiry + re-access model — RESOLVED 2026-04-02

30-day expiry is correct. view_token tied to same token is fine. Cleanup cron handles expired rows.
