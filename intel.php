<?php
/**
 * The Community Block List was retired in v5.0.0 (IPG-23). This page never
 * touches the database. Every request, including the old ?format= download
 * URLs, gets the same 410, so a firewall script still pulling the list fails
 * loudly instead of receiving a page of HTML.
 * The community_* tables are kept for now. The old page and its download
 * code are in git history.
 */

require __DIR__ . '/includes/page-chrome.php';

http_response_code(410);

render_page_open('Community Block List retired — ip2geo.org', 'The Community Block List was retired in v5.0.0. The bulk lookup is still free and right here.');
?>
<section class="report-section">
    <div class="report-inner">
        <div class="section-head">
            <h1>Community Block List retired</h1>
            <span class="section-tag">/ 410 Gone</span>
        </div>
        <div class="prose">
            <p>The Community Block List was retired in v5.0.0. The bulk lookup is still free and right here.</p>
            <p><a href="/">Go to the lookup &rarr;</a></p>
        </div>
    </div>
</section>
<?php render_page_close(); ?>
