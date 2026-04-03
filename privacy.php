<!DOCTYPE HTML>
<!--
	Hyperspace by HTML5 UP
	html5up.net | @ajlkn
	Free for personal and commercial use under the CCA 3.0 license (html5up.net/license)
-->
<html>
	<head>
		<!-- Umami (production only) -->
		<?php if ($_SERVER['HTTP_HOST'] === 'ip2geo.org'): ?>
		<script defer src="https://cloud.umami.is/script.js" data-website-id="656d7a15-6282-4079-af1e-b8ed857fba2e"></script>
		<?php endif; ?>
		<title>ip2geo.org Privacy Policy</title>
		<meta charset="utf-8" />
		<meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=no" />
		<link rel="stylesheet" href="assets/css/main.css" />
		<link rel="icon" href="/favicon.ico" />
		<noscript><link rel="stylesheet" href="assets/css/noscript.css" /></noscript>
	</head>
	<body class="is-preload">

		<!-- Header -->
			<header id="header">
				<a href="/" class="title">ip2geo.org</a>
				<nav>
					<ul>
						<li><a href="/">Home</a></li>
					</ul>
				</nav>
			</header>

		<!-- Wrapper -->
			<div id="wrapper">

				<!-- Main -->
					<section id="main" class="wrapper">
						<div class="inner">
							<h1 class="major">Privacy Policy</h1>
							<p>This privacy notice discloses the privacy practices for <span style="text-decoration: underline;">ip2geo.org</span>. This privacy notice applies solely to information collected by this website. It will notify you of the following:</p>
							<ol type="1">
							<li>What personally identifiable information is collected from you through the website, how it is used and with whom it may be shared.</li>
							<li>The security procedures in place to protect the misuse of your information.</li>
							</ol>
							<h3>Information Collection, Use, and Sharing</h3>
							<p>We are the sole owners of the information collected on this site. We only have access to/collect information that you voluntarily give us via email, direct contact, or use of site features. We will not sell or rent this information to anyone.</p>
							<p>IP lookups on the main tool are not logged and any data used is transient. Visitor analytics are collected via <a href="https://umami.is/" target="_blank">Umami</a>, an open-source, privacy-friendly analytics platform that does not use cookies or share data with third parties.</p>
							<h3>Threat Reports</h3>
							<p>When you purchase a Threat Report, the IP addresses you submit and the resulting report are stored securely for 30 days, after which they are deleted. If you provide an email address to receive your report, that address is stored alongside your report and is permanently deleted when the report expires or is removed early. This data is accessible only via your unique report token.</p>
							<p>To generate your report, the top IP addresses by frequency are checked against <a href="https://www.abuseipdb.com/" target="_blank">AbuseIPDB</a>, a third-party IP reputation service. This sends a subset of your submitted IPs to AbuseIPDB solely to retrieve abuse confidence scores. AbuseIPDB's use of this data is governed by their <a href="https://www.abuseipdb.com/privacy-policy" target="_blank">Privacy Policy</a>.</p>
							<p>Payment is processed by <a href="https://stripe.com" target="_blank">Stripe</a>. We do not collect or store your payment card details. Stripe may collect your name, email address, card details, and billing information in accordance with their <a href="https://stripe.com/privacy" target="_blank">Privacy Policy</a>.</p>
							<h3>Community Threat Intelligence</h3>
							<p>When you opt in on your report page, anonymized data from your Threat Report may contribute to ip2geo's community threat feed. Specifically: CIDR network ranges and individual IP addresses classified as scanning or VPN/proxy infrastructure. Residential IP addresses are never collected.</p>
							<p>No individual report data, tokens, email addresses, or personally identifiable information is included in the aggregate. The aggregate tables contain only network ranges, IP addresses, and counts — with no link back to the contributing report.</p>
							<p>Consent is opt-in only, requested on your report page after generation. Each report is an independent purchase with its own consent decision &mdash; there is no account or cross-purchase tracking. Because contributed data is immediately aggregated with no user identifier retained, individual contributions cannot be separated from the aggregate after the fact. If you wish to mark a specific report as opted-out (contact <a href="mailto:support@ip2geo.org">support@ip2geo.org</a> with your report token), we will update the record to prevent re-ingestion if community data is re-processed before the report's 30-day permanent deletion. However, data already in the aggregate cannot be removed. This is consistent with GDPR Recital 26: truly anonymized data is not subject to erasure requirements.</p>
							<h3>Contact</h3>
							<p>Questions about this policy or your data can be directed to <a href="mailto:support@ip2geo.org">support@ip2geo.org</a>. If you would like your report data deleted before the 30-day expiry, contact us with your report token and we will remove it promptly.</p>
							<h3>Security</h3>
							<p>All data is transmitted over HTTPS. You can verify this by looking for a lock icon in the address bar and "https" at the beginning of the page address.</p>
						</div>
					</section>

			</div>

	<?php require __DIR__ . '/includes/footer.php'; ?>

		<!-- Scripts -->
			<script src="assets/js/jquery.min.js"></script>
			<script src="assets/js/jquery.scrollex.min.js"></script>
			<script src="assets/js/jquery.scrolly.min.js"></script>
			<script src="assets/js/browser.min.js"></script>
			<script src="assets/js/breakpoints.min.js"></script>
			<script src="assets/js/util.js"></script>
			<script src="assets/js/main.js"></script>

	</body>
</html>
