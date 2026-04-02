<!DOCTYPE HTML>
<!--
	Hyperspace by HTML5 UP
	html5up.net | @ajlkn
	Free for personal and commercial use under the CCA 3.0 license (html5up.net/license)
-->
<html>
	<head>
		<!-- Umami -->
		<script defer src="https://cloud.umami.is/script.js" data-website-id="656d7a15-6282-4079-af1e-b8ed857fba2e"></script>
		<title>ip2geo.org Changelog</title>
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
							<h1 class="major">Changelog</h1>
								<h3>3.0.0 - 2026-04-02</h3>
							<p>ip2geo now does something genuinely new: upload your server logs, and it tells you what's actually hitting you. The lookup tool is still here, but it's now joined by Threat Reports — paste in a batch of IPs from your access logs, pay once, and get back a full threat assessment: a verdict (clean, watchlist, or threat), a breakdown of scanning and proxy infrastructure, AbuseIPDB abuse scores for the worst offenders, and ASN CIDR ranges grouped by network so you can block the whole subnet instead of playing whack-a-mole with individual addresses.</p>
							<p>The actionable part: ready-to-run block scripts for iptables, ufw, and nginx, generated for both individual IPs and CIDR ranges, downloadable directly from the report. Reports are tied to a token and expire after 30 days. Stripe handles payment. The webhook handler, token lifecycle, and report generation are all tested — 95 unit tests, 119 assertions, covering verdict logic, token states, AbuseIPDB ranking, ASN classification, and the webhook handler.</p>
								<h3>2.6.3 - 2026-03-23</h3>
							<p>Swapped Google Analytics for <a href="https://umami.is/" target="_blank">Umami</a>. Same lookup and CSV download events are tracked, same visitor stats — just without sending your data to Google first. Umami is open-source and privacy-friendly, which feels more in keeping with a tool that doesn't log IPs.</p>
							<h3>2.6.2 - 2026-03-13</h3>
							<p>Removed the PayPal donation button. Coffee is better anyway, and PayPal's UX is bad.</p>
							<h3>2.6.1 - 2026-03-13</h3>
							<p>Housekeeping ahead of open-sourcing the repo:</p>
							<ul>
								<li>Added defensive HTML escaping.</li>
								<li>Tidied internal server references out of CI workflow comments.</li>
								<li>Removed a dead Google Universal Analytics snippet still haunting a couple of pages.</li>
								<li>Fixed testing tools to use <code>random_int()</code> so generated test IPs actually cover the full IPv4 address space.</li>
							</ul>
							<h3>2.6.0 - 2026-03-13</h3>
							<p>The IP lookup engine got a meaningful tune-up, cutting per-IP database time by about 60%. That cuts a 10,000-IP lookup from roughly 4.5 seconds of database time down to under 2. The site also now fires two Google Analytics events for CSV downloads and <code>ip_count</code>, so there's finally a wee little data on how ip2geo is being used being collected. (All of which is still blocked by ad blocker extensions or your friendly neighborhood <a href="https://pi-hole.net/" target="_blank">pi-hole</a>.)</p>
							<h3>2.5.1 - 2026-03-13</h3>
							<p>Historical cruft cleanup.</p>
							<h3>2.5.0 - 2026-03-13</h3>
							<p>Submitting a large batch of IPs used to mean staring at a blank page for several seconds. No more. The form now submits via AJAX and a full-viewport loading overlay appears immediately showing how many IPs are being processed and stays visible until results are ready. The overlay falls back gracefully to a normal form submit if JavaScript isn't available. Page load transitions are also faster site-wide.</p>
							<h3>2.4.0 - 2026-03-12</h3>
							<p>Two releases in one day. We're on a roll. Results are now exportable: a Download CSV button appears above the table after any lookup, generating a properly-quoted RFC 4180 file client-side with no second round-trip to the server. IPs that returned no geo data get their own toggleable section so they're out of the way but not silently discarded. The summary stats below results got a full makeover — monospace, column-aligned, and actually informative (submitted vs. matched vs. filtered vs. unresolved, all accounted for). Also quietly retired <code>about.php</code> and its legacy UA analytics snippet, which had no business still existing.</p>
							<h3>2.3.0 - 2026-03-12</h3>
							<p>Taught ip2geo.org to update its own data. MaxMind's GeoLite2-City database now refreshes automatically on the first of every month: downloaded, converted, imported into shadow tables, verified against a known IP, then swapped in atomically while the old data keeps serving. If anything looks off, it rolls back and files a strongly-worded GitHub Actions failure notification. Also added a data freshness date to the footer, because it turns out people care how old their geolocation data is.</p>
							<h3>2.2.0 - 2026-03-11</h3>
							<p>Security hardening and grown-up deployment infrastructure. Fixed a handful of XSS vectors (nothing to see here), added a 2MB input cap, and corrected a bug that was silently discarding the <em>first</em> batch of IPs instead of the last. The old versioned index files are gone and git is the version history now, as it was always meant to be. Also introduced a full CI/CD pipeline with a staging environment, because apparently this is a serious project.</p>
							<h3>2.1.1 - 2025-04-05</h3>
							<p>Bugfix. Introduction of Changelog. Removed defunct twitter link. Made "About" section slightly more professional (slightly).</p>
							<h3>2.1.0 - 2025-04-04</h3>
							<p>Refactor database query approach. ~12% speed improvement through preconverting IPv4 addresses and avoiding INET6_ATON.</p>
							<h3>2.0.7 - 2025-04-04</h3><p>Maxmind database update (2025-04-01).</p>
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
