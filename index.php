<?php

require __DIR__ . '/config.php';
@include_once __DIR__ . '/db_version.php'; // gitignored; written by the monthly DB update script

function getRealIPAddr()
{
  //check ip from share internet
  if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
    $ip = $_SERVER['HTTP_CLIENT_IP'];
  }
  //to check ip is pass from proxy
  elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
  } else {
    $ip = $_SERVER['REMOTE_ADDR'];
  }

  return $ip;
}

function ipToLong(string $ip): string {
    return sprintf('%u', ip2long($ip)); // Handles unsigned 32-bit int
}


?><!DOCTYPE HTML>
<!--
	Hyperspace by HTML5 UP
	html5up.net | @ajlkn
	Free for personal and commercial use under the CCA 3.0 license (html5up.net/license)
-->
<html lang="en">
	<head>
		<!-- Google tag (gtag.js) -->
		<script async src="https://www.googletagmanager.com/gtag/js?id=G-RZE952QHFN"></script>
		<script>
		  window.dataLayer = window.dataLayer || [];
		  function gtag(){dataLayer.push(arguments);}
		  gtag('js', new Date());

		  gtag('config', 'G-RZE952QHFN');
		</script>
		<title>Bulk IP Lookup & Location Finder - Free IP Geolocation Lookup Tool</title>
		<meta charset="utf-8" />
		<meta name="description" content="Free tool to filter up to 10,000 IP addresses from an arbitrary text blob and list their geographic location." />
		<meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=no" />
		<link rel="stylesheet" href="assets/css/main.css" />
		<noscript><link rel="stylesheet" href="assets/css/noscript.css" /></noscript>
	</head>
	<body class="is-preload">

		<!-- Sidebar -->
	    <section id="sidebar">
	        <div class="inner">
	            <nav>
	                <ul>
	                    <li><a href="#intro">Bulk IP Location Lookup</a></li>
	                    <li><a href="#contribute">Contact / Contribute</a></li>
	                    <li><a href="#about">About</a></li>
	                </ul>
	            </nav>
	        </div>
	    </section>

		<!-- Wrapper -->
			<div id="wrapper">

				<!-- Intro -->
					<section id="intro" class="wrapper style4 fade-up">
						<div class="inner">
							<h1>ip2geo Lookup</h1>
							<p>Enter an IPv4 address (or 10,000) below and hit "Look Up IP Addresses" to find a general geographic area or city the IP is registered to. Any non-IP text is stripped, so feel free to just paste your whole log file, netstat output, or whatever pile of plain text that includes some IPs you want to check (as long as it's less than 2MB).</p>
							<div class="style1">
								<section>
									<form action="#results" method="post" name="ip_entry" id="iplookup">
										<div class="fields">
											<div class="field">
												<label for="message">Text containing IPv4 Addresses</label>
												<textarea name="ip_list" id="message" rows="5"><?php
if(!isset($_POST['ip_list']))
{
	echo "Here's some example text with the IPs 8.8.8.8 (Google's public DNS) and @#75.75.75.75@#% (Comcast's DNS with some extra characters tucked in the middle). Hit the button below to try it out. We'll see about your IP (".htmlspecialchars(getRealIPAddr(), ENT_QUOTES, 'UTF-8').") too, assuming it's IPv4.";
} else {
	echo htmlspecialchars($_POST['ip_list'], ENT_QUOTES, 'UTF-8');
}
		?></textarea>
											</div>
											<div class="field half">
												<label for="countries_filter">Countries to exclude</label>
												<input type="text" id="countries_filter" name="countries_filter" value="<?php if (isset($_POST['countries_filter'])) { echo htmlspecialchars(strtoupper($_POST['countries_filter']), ENT_QUOTES, 'UTF-8'); } ?>" />
												<sub><a href="https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2" target="_blank">2-letter ISO codes</a>, i.e. US CA GB. Use to filter out non-suspicious IPs.</sub>
											</div>
											<div class="field half">
												<label for="email">&nbsp;</label>
												<input type="submit" class="submit" value="Look Up IP Addresses" />
											</div>
										</div>
									</form>
								</section>
							</div>
						</div>
					</section>

<?php


if($_POST)
{
	$con = mysqli_connect($db_host, $db_user, $db_pass, $db_name);
	if (mysqli_connect_errno())
	{
		error_log("ip2geo DB connection failed: " . mysqli_connect_error());
		echo "Database connection failed. Please try again later.";
	}

	// Get Country List
	$countries_query = 'SELECT DISTINCT(`country_iso_code`) FROM `geoip2_location_current` WHERE `country_iso_code` IS NOT NULL';
	$countries = mysqli_query($con,$countries_query);
	while($row = mysqli_fetch_array($countries))
	{
		$countries_all[$row['country_iso_code']] = $row['country_iso_code'];
	}
	$countries_all = array_filter($countries_all); // remove random blank from unknown source wtf?

	// now parse country box / strip bad shit / escape all the things
	$good_countries = array_filter(explode(" ", mysqli_real_escape_string($con,strtoupper($_POST['countries_filter']))));
	foreach ($good_countries as $key => $value) {
		if(!in_array($value, $countries_all))
		{
			// echo 'unset('.$good_countries[$key].');<br/>';
			unset($good_countries[$key]);
		}
	}

	// Make an Array of valid IPs out of the input
	if (strlen($_POST['ip_list']) > 2097152) { // 2MB hard limit
		echo '<section id="results" class="wrapper style4 fade-up"><div class="inner"><p>Input exceeds 2MB limit. Please reduce the size of your input.</p></div></section>';
		exit;
	}
	preg_match_all("/\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/",$_POST['ip_list'],$ip_list);
	// $ip_list = array_unique(array_filter(filter_var_array(explode("\r\n", $_POST['ip_list']), FILTER_VALIDATE_IP)));

	// Strip: non-IPs, duplicates
	$ip_list = filter_var_array(array_unique($ip_list[0]));
	$ip_list = array_slice($ip_list, 0, 10000);

	// strip local ips
	function test_local($ip_to_test)
	{
		// Ignore Local & NAT-only IPs
		if (!preg_match("/(^127\.)|(^192\.168\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^::1$)/", $ip_to_test))
		{
			return true;
		}
	}
	$ip_list = array_filter($ip_list, "test_local");

	// What're our acceptable countries?
	// $good_countries = array('US','CA');

	$matches_total = 0;
	$filtered_total = 0;
	$no_result_ips = [];
	$totalduration = 0;
	$rows_html = '';
	foreach ($ip_list as $key => $ip) {
		$ip = mysqli_real_escape_string($con,$ip); // Just in case of crazy awesome hackers, escape our IP "input"
		$query = 'SELECT country_iso_code, country_name, subdivision_1_name, city_name FROM( SELECT * FROM geoip2_network_current_int WHERE "'.ipToLong($ip).'" >= network_start_integer ORDER BY network_start_integer DESC LIMIT 1) net LEFT JOIN geoip2_location_current location ON ( net.geoname_id = location.geoname_id AND location.locale_code = "en" ) WHERE "'.ipToLong($ip).'" <= network_end_integer';
		// $query = 'SELECT country_iso_code,country_name,city_name FROM locations WHERE `geoname_id` = (SELECT geoname_id FROM `blocks` INNER JOIN (SELECT MAX(start_ip) AS start FROM `blocks` WHERE start_ip <= INET_ATON("'.$ip.'")) AS s ON (start_ip = s.start) WHERE end_ip >= INET_ATON("'.$ip.'"))';
		$starttime = microtime(true);
		$result = mysqli_query($con,$query);
		$endtime = microtime(true);
		$duration = $endtime - $starttime;
		$geo_found = false;
		while($row = mysqli_fetch_array($result))
		{
			$geo_found = true;
			if(!in_array($row['country_iso_code'],$good_countries))
			{
				$rows_html .= '<tr>';
				$rows_html .= '<td>'.$ip.'</td>';
				$rows_html .= '<td>'.$row['country_iso_code'].'</td>';
				$rows_html .= '<td>'.$row['country_name'].'</td>';
				$rows_html .= '<td>'.$row['subdivision_1_name'].'</td>';
				$rows_html .= '<td>'.$row['city_name'].'</td>';
				$rows_html .= '</tr>';
				$matches_total++;
			} else {
				$filtered_total++;
			}
		}
		if (!$geo_found) $no_result_ips[] = $ip;
		$totalduration = $totalduration + $duration;
	}

	// --- Output results section (counts are now known) ---
	echo '<section id="results" class="wrapper style4 fade-up"><div class="inner"><div class="table-wrapper">';
	echo '<h2 id="result">Lookup Results</h2>';
	echo '<p style="margin-bottom:1em">';
	echo '<button id="download-csv" class="button small">&#8595; Download CSV</button>';
	if (!empty($no_result_ips)) {
		$n = count($no_result_ips);
		echo ' <button id="toggle-unresolved" class="button small alt">Show '.$n.' unresolved IP'.($n !== 1 ? 's' : '').'</button>';
	}
	echo '</p>';

	echo '<table id="results-table"><thead><th>IP</th><th>Country Code</th><th>Country</th><th>State/Province</th><th>City</th></thead><tbody>';
	echo $rows_html;
	echo '</tbody>';

	if (!empty($no_result_ips)) {
		echo '<tbody id="unresolved-rows" style="display:none">';
		foreach ($no_result_ips as $unresolved_ip) {
			echo '<tr><td>'.htmlspecialchars($unresolved_ip, ENT_QUOTES, 'UTF-8').'</td><td></td><td></td><td></td><td></td></tr>';
		}
		echo '</tbody>';
	}

	echo '</table></div>';

	// --- Summary stats ---
	$submitted = count($ip_list);
	echo '<table style="font-family:monospace;font-size:0.8em;border-collapse:collapse;margin-top:0.5em">';
	echo '<tr><td style="padding:1px 1em 1px 0;text-align:right">'.$submitted.'</td><td>IP'.($submitted !== 1 ? 's' : '').' submitted (valid, unique, non-private)</td></tr>';
	echo '<tr><td style="padding:1px 1em 1px 0;text-align:right">'.$matches_total.'</td><td>returned geo results</td></tr>';
	if ($filtered_total > 0) {
		echo '<tr><td style="padding:1px 1em 1px 0;text-align:right">'.$filtered_total.'</td><td>excluded by country filter</td></tr>';
	}
	echo '<tr><td style="padding:1px 1em 1px 0;text-align:right">'.count($no_result_ips).'</td><td>returned no geo data</td></tr>';
	echo '<tr><td style="padding:1px 1em 1px 0;text-align:right">'.round($totalduration,3).'s</td><td>query duration</td></tr>';
	if (!empty($good_countries)) {
		echo '<tr><td style="padding:1px 1em 1px 0;text-align:right">—</td><td>excluded countries: '.htmlspecialchars(implode(' ', $good_countries)).'</td></tr>';
	}
	echo '</table>';

	// --- Inline JS: CSV download + unresolved toggle ---
	?>
	<script>
	(function() {
		// CSV download
		document.getElementById('download-csv').addEventListener('click', function() {
			var bom = '\uFEFF';
			var headers = ['IP','Country Code','Country','State/Province','City'];
			var rows = [headers];
			var trs = document.querySelectorAll('#results-table tbody tr');
			trs.forEach(function(tr) {
				if (tr.parentElement.style.display === 'none') return;
				var cols = tr.querySelectorAll('td');
				var row = [];
				cols.forEach(function(td) {
					var val = td.textContent.replace(/"/g, '""');
					row.push(/[,"\n]/.test(val) ? '"' + val + '"' : val);
				});
				rows.push(row);
			});
			var csv = bom + rows.map(function(r) { return r.join(','); }).join('\r\n');
			var a = document.createElement('a');
			a.href = URL.createObjectURL(new Blob([csv], {type: 'text/csv;charset=utf-8;'}));
			a.download = 'ip2geo-results.csv';
			a.click();
			URL.revokeObjectURL(a.href);
		});

		// Toggle unresolved rows
		var toggleBtn = document.getElementById('toggle-unresolved');
		if (toggleBtn) {
			var unresolvedBody = document.getElementById('unresolved-rows');
			var n = unresolvedBody.rows.length;
			toggleBtn.addEventListener('click', function() {
				var hidden = unresolvedBody.style.display === 'none';
				unresolvedBody.style.display = hidden ? '' : 'none';
				toggleBtn.textContent = (hidden ? 'Hide ' : 'Show ') + n + ' unresolved IP' + (n !== 1 ? 's' : '');
			});
		}
	})();
	</script>
	<?php
	echo '</section></section>';
}
else
{
	echo '<!--';
	//echo '<iframe src="/about.php" style="" />';
	echo '-->';
}

?>


				<!-- Contact / Contribute -->
		        <section id="contribute" class="wrapper style1 fade-up">
		            <div class="inner">
		            	<h2>Contact / Contribute</h2>
		            	<p>ip2geo.org is maintained and run by me, Josh. Hi. If this tool was helpful, feel free to say hello &mdash; or help contribute to hosting if this really saved the day.</p>
		        		<div class="row">
		                <div class="col-6 col-12-medium">
		                    <ul class="contact">
		                        <li>
		                        	<h3>Social</h3>
		                            <ul>
		                                <li><a href="https://joshgister.com/" target="_blank">Personal Site</a></li>
		                                <li><a href="https://www.linkedin.com/in/joshgister/" target="_blank">LinkedIn</a></li>
		                                <li><a rel="me" href="https://ioc.exchange/@joshgister" target="_blank">Mastodon</a></li>
		                            </ul>
		                        </li>
		                	</ul>
		                </div>
		                <div class="col-6 col-12-medium">
		                	<ul class="contact">
		                        <li>
		                        	<h3>Donate</h3>
		                            <ul>
		                                <li><a href="https://www.buymeacoffee.com/ip2geo" target="_blank">Buy me a coffee</a></li>
		                                <li>Paypal &mdash;<form action="https://www.paypal.com/cgi-bin/webscr" method="post" target="_top"><input type="hidden" name="cmd" value="_s-xclick"><input type="hidden" name="encrypted" value="-----BEGIN PKCS7-----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-----END PKCS7-----"><input type="image" src="https://www.paypalobjects.com/en_US/i/btn/btn_donate_SM.gif" border="0" name="submit" alt="PayPal - The safer, easier way to pay online!"><img alt="" border="0" src="https://www.paypalobjects.com/en_US/i/scr/pixel.gif" width="1" height="1"></form></li>
		                            </ul>
		                        </li>
		                    </ul>
		            	</div>
		            </div></div>
		        </section>


				<!-- About -->
				<section id="about" class="wrapper style4 fade-up">
					<div class="inner">
						<section>
							<h2>About ip2geo.org</h2>
							<h3>Why This Exists</h3>
							<p>Ever been on the wrong end of a distributed probe hammering away at your email server, SSH port, or some other exposed service? It's chaos. Logs scroll by like a waterfall, and your tools? They're powerful, sure — but not exactly friendly when you're trying to make sense of hundreds of connections in real time.</p>
							<h3>The Problem</h3>
							<p>You run a CLI command, grab the output, and paste it into your favorite text editor. You start cleaning it up, extracting IPs manually, only to hit a wall: now you're supposed to copy-paste those addresses into a web form. One by one. Seriously?</p>
							<p>When you're facing a flood of suspicious traffic, that's just not going to cut it.</p>
							<h3>The Fix</h3>
							<p>I was maintaining an aging email system with no password policies and no support — a perfect storm for account compromises. With no time or budget to overhaul it, I built this tool instead.</p>
							<p>ip2geo.org lets you paste raw output from tools like <code>netstat</code>, <code>fail2ban</code>, or anything else that spits out IPs. It automatically extracts valid IPv4 addresses, runs a fast geolocation lookup, and gives you clean, actionable data — instantly. With one glance, I could see login attempts from every corner of the globe and quickly block entire botnets.</p>
							<h3>How It Works</h3>
							<p>Paste any block of text. ip2geo.org scans it for IPv4 addresses, checks them against a geolocation database, and returns results you can filter by country. Want to ignore U.S. traffic while investigating a weird spike in Romania? Done. Focus only on what matters.</p>
							<h3>Why It's Free</h3>
							<p>This tool was built using free and open-source resources, and it's free because I wish something like this had existed when I needed it most. If it helps you too, consider <a href="https://www.buymeacoffee.com/ip2geo" target="_blank">buying me a coffee</a> or tossing a few bucks toward hosting costs.</p>
						</section>
					</div>
				</section>

			</div>

		<!-- Footer -->
			<footer id="footer" class="wrapper style1-alt">
				<div class="inner">
					<ul class="menu">
						<li>This product includes GeoLite2 data created by MaxMind, available from <a href="http://www.maxmind.com" target="_new">http://www.maxmind.com</a>.</li>
					</ul>
					<ul class="menu">
						<li><a href="/changelog.php">v2.3.0</a> &ndash; &copy;<?php echo date("Y"); ?></li>
						<?php if (!empty($db_data_date)) { echo '<li>Data: ' . $db_data_date . '</li>'; } ?>
						<li><a href="/privacy.php">Privacy Policy</a></li>
						<li>Design: <a href="http://html5up.net">HTML5 UP</a></li>
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
