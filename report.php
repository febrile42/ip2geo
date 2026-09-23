<?php
/**
 * Threat Reports were retired in v5.0.0 (R17). This page never touches the
 * database — any token, or no token at all, gets the same 410 response.
 * Kept at this path (instead of deleting the file) so old links and search
 * results land somewhere explanatory instead of a raw 404.
 */

require __DIR__ . '/includes/page-chrome.php';

http_response_code(410);

render_page_open('Threat Reports retired — ip2geo.org', 'Threat Reports were retired in v5.0.0. The bulk lookup is still free and right here.');
?>
<section class="report-section">
    <div class="report-inner">
        <div class="section-head">
            <h1>Threat Reports retired</h1>
            <span class="section-tag">/ 410 Gone</span>
        </div>
        <div class="prose">
            <p>Threat Reports were retired in v5.0.0. The bulk lookup is still free and right here.</p>
            <p><a href="/">Go to the lookup &rarr;</a></p>
        </div>
    </div>
</section>
<?php render_page_close(); ?>
