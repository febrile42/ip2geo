<?php
require __DIR__ . '/includes/page-chrome.php';
render_page_open('Privacy Policy — ip2geo.org', 'How ip2geo.org collects, stores, and shares data.');
?>
<section class="report-section">
    <div class="report-inner">
        <div class="section-head">
            <h1>Privacy Policy</h1>
            <span class="section-tag">/ Privacy</span>
        </div>

        <div class="prose">
            <p>This privacy notice discloses the privacy practices for <u>ip2geo.org</u>. This privacy notice applies solely to information collected by this website. It will notify you of the following:</p>
            <ol>
                <li>What personally identifiable information is collected from you through the website, how it is used and with whom it may be shared.</li>
                <li>The security procedures in place to protect the misuse of your information.</li>
            </ol>

            <h3>Information Collection, Use, and Sharing</h3>
            <p>We are the sole owners of the information collected on this site. We only have access to/collect information that you voluntarily give us via email, direct contact, or use of site features. We will not sell or rent this information to anyone.</p>
            <p>IP lookups on the main tool are not logged. The log text you paste stays in your browser and is never sent anywhere; only the IP addresses extracted from it are sent to our server, which looks them up and does not store them. Visitor analytics are collected via a self-hosted instance of <a href="https://umami.is/" target="_blank" rel="noopener">Umami</a>, an open-source, privacy-friendly analytics platform that does not use cookies or share data with third parties.</p>
            <p>Some features store small amounts of data locally in your browser (for example, your theme preference and, if enabled, your recent lookups). This information stays on your device, is never transmitted to us, and can be cleared at any time through your browser settings.</p>

            <h3>Community Threat Intelligence</h3>
            <p>ip2geo maintains a community threat feed built from anonymized, opted-in contributions: CIDR network ranges and individual IP addresses classified as scanning or VPN/proxy infrastructure. Residential IP addresses are never collected.</p>
            <p>No tokens, email addresses, or other personally identifiable information is included in the aggregate. The aggregate tables contain only network ranges, IP addresses, and counts &mdash; with no link back to any individual contribution. Consent is opt-in only. Because contributed data is immediately aggregated with no user identifier retained, individual contributions cannot be separated from the aggregate after the fact; this is consistent with GDPR Recital 26, which excludes truly anonymized data from erasure requirements.</p>

            <h3>Contact</h3>
            <p>Questions about this policy or your data can be directed to <a href="&#109;&#97;&#105;&#108;&#116;&#111;&#58;&#115;&#117;&#112;&#112;&#111;&#114;&#116;&#64;&#105;&#112;&#50;&#103;&#101;&#111;&#46;&#111;&#114;&#103;">&#115;&#117;&#112;&#112;&#111;&#114;&#116;&#64;&#105;&#112;&#50;&#103;&#101;&#111;&#46;&#111;&#114;&#103;</a>.</p>

            <h3>Security</h3>
            <p>All data is transmitted over HTTPS. You can verify this by looking for a lock icon in the address bar and "https" at the beginning of the page address.</p>
        </div>
    </div>
</section>
<?php render_page_close(); ?>
