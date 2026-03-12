<!DOCTYPE HTML>
<!--
	Hyperspace by HTML5 UP
	html5up.net | @ajlkn
	Free for personal and commercial use under the CCA 3.0 license (html5up.net/license)
-->
<html>
	<head>
		<!-- Google tag (gtag.js) -->
		<script async src="https://www.googletagmanager.com/gtag/js?id=G-RZE952QHFN"></script>
		<script>
		  window.dataLayer = window.dataLayer || [];
		  function gtag(){dataLayer.push(arguments);}
		  gtag('js', new Date());

		  gtag('config', 'G-RZE952QHFN');
		</script>
		<title>ip2geo.org Changelog</title>
		<meta charset="utf-8" />
		<meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=no" />
		<link rel="stylesheet" href="assets/css/main.css" />
		<noscript><link rel="stylesheet" href="assets/css/noscript.css" /></noscript>
	</head>
	<body class="is-preload">
<script>
  (function(i,s,o,g,r,a,m){i['GoogleAnalyticsObject']=r;i[r]=i[r]||function(){
  (i[r].q=i[r].q||[]).push(arguments)},i[r].l=1*new Date();a=s.createElement(o),
  m=s.getElementsByTagName(o)[0];a.async=1;a.src=g;m.parentNode.insertBefore(a,m)
  })(window,document,'script','https://www.google-analytics.com/analytics.js','ga');

  ga('create', 'UA-102801602-1', 'auto');
  ga('send', 'pageview');

</script>

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
							<h3>2.3.0 - 2026-03-12</h3>
						<p>Taught ip2geo.org to update its own data. MaxMind's GeoLite2-City database now refreshes automatically on the first of every month — downloaded, converted, imported into shadow tables, verified against a known IP, then swapped in atomically while the old data keeps serving. If anything looks off, it rolls back and files a strongly-worded GitHub Actions failure notification. Also added a data freshness date to the footer, because it turns out people care how old their geolocation data is.</p>
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

		<!-- Footer -->
		<!-- Footer -->
			<footer id="footer" class="wrapper style1-alt">
				<div class="inner">
					<ul class="menu">
						<li>This product includes GeoLite2 data created by MaxMind, available from <a href="http://www.maxmind.com" target="_new">http://www.maxmind.com</a>.</li>
					</ul>
					<ul class="menu">
						<li>&copy;<?php echo date("Y"); ?></li>
						<li><a href="/privacy.php">Privacy Policy</a></li>
						<li>Design: <a href="http://html5up.net" target="_blank">HTML5 UP</a></li>
					</ul>
				</div>
			</footer>

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
