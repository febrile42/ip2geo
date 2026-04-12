<?php

require __DIR__ . '/config.php';
require __DIR__ . '/asn_classification.php';
@include_once __DIR__ . '/db_version.php'; // gitignored; written by the monthly DB update script

function getRealIPAddr()
{
	// Check for IP from shared internet / proxy
	if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
		$ip = $_SERVER['HTTP_CLIENT_IP'];
	}
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

// view_token mode: show all IPs for a paid/redeemed report without a new submission
$view_token_mode = !empty($_GET['view_token']) && empty($_POST);
$view_token_val  = $view_token_mode ? preg_replace('/[^a-f0-9\-]/', '', trim($_GET['view_token'])) : '';


?><!DOCTYPE HTML>
<!--
	Hyperspace by HTML5 UP
	html5up.net | @ajlkn
	Free for personal and commercial use under the CCA 3.0 license (html5up.net/license)
-->
<html lang="en">
	<head>
		<!-- Umami (production only) -->
		<?php if ($_SERVER['HTTP_HOST'] === 'ip2geo.org'): ?>
		<script defer src="https://cloud.umami.is/script.js" data-website-id="656d7a15-6282-4079-af1e-b8ed857fba2e"></script>
		<?php endif; ?>
		<title>Bulk IP Lookup & Location Finder - Free IP Geolocation Lookup Tool</title>
		<meta charset="utf-8" />
		<meta name="description" content="Free tool to filter up to 10,000 IP addresses from an arbitrary text blob and list their geographic location." />
		<meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=no" />
		<link rel="stylesheet" href="assets/css/main.css" />
	<link rel="stylesheet" href="assets/css/ip2geo-app.css" />
		<link rel="icon" href="/favicon.ico" />
		<noscript><link rel="stylesheet" href="assets/css/noscript.css" /></noscript>
	</head>
	<body class="is-preload">

		<!-- Sidebar -->
		<section id="sidebar">
			<div class="inner">
				<nav>
					<ul>
						<li><a href="#intro">Bulk IP Location Lookup</a></li>
						<li><a href="#reports">Threat Reports</a></li>
						<li><a href="/intel.php" target="_blank" rel="noopener noreferrer">Community Block List <i class="fas fa-external-link-alt" style="font-size:0.7em;opacity:0.6;vertical-align:middle"></i></a></li>
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
if ($view_token_mode) {
	// leave empty — user's IPs not re-populated in view mode
} elseif (!isset($_POST['ip_list'])) {
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


if ($_POST || $view_token_mode)
{
	$con = mysqli_connect($db_host, $db_user, $db_pass, $db_name);
	if (mysqli_connect_errno())
	{
		error_log("ip2geo DB connection failed: " . mysqli_connect_error());
		echo "Database connection failed. Please try again later.";
	}

	if ($view_token_mode) {
		// Load the original IP list from a paid/redeemed report token
		$stmt = $con->prepare(
			'SELECT ip_list_json, geo_results_json FROM reports WHERE token = ? AND status IN ("paid","redeemed")'
		);
		$stmt->bind_param('s', $view_token_val);
		$stmt->execute();
		$vt_row = $stmt->get_result()->fetch_assoc();
		$stmt->close();

		if (!$vt_row) {
			echo '<section id="results" class="wrapper style4 fade-up"><div class="inner">';
			echo '<p>Report not found or access has expired. <a href="/" class="button small">&#8592; New Lookup</a></p>';
			echo '</div></section>';
			mysqli_close($con);
			$con = null;
		} else {
			$vt_ip_data = json_decode($vt_row['ip_list_json'], true) ?? [];
			$ip_freq = [];
			foreach ($vt_ip_data as $entry) {
				$vt_ip = $entry['ip'] ?? '';
				if ($vt_ip !== '') $ip_freq[$vt_ip] = $entry['freq'] ?? 1;
			}
			$ip_list = array_keys($ip_freq);
			$good_countries = []; // show all IPs — no country filter in view mode
			$vt_geo_cached = !empty($vt_row['geo_results_json'])
				? (json_decode($vt_row['geo_results_json'], true) ?? [])
				: [];
		}
	}

	if ($_POST) {
		// Get Country List
		$countries_query = 'SELECT DISTINCT(`country_iso_code`) FROM `geoip2_location_current` WHERE `country_iso_code` IS NOT NULL';
		$countries = mysqli_query($con, $countries_query);
		while ($row = mysqli_fetch_array($countries))
		{
			$countries_all[$row['country_iso_code']] = $row['country_iso_code'];
		}
		$countries_all = array_filter($countries_all); // remove spurious empty entries

		// parse country filter: normalize, sanitize, and validate against known country codes
		$good_countries = array_filter(explode(" ", mysqli_real_escape_string($con, strtoupper($_POST['countries_filter'] ?? ''))));
		foreach ($good_countries as $key => $value) {
			if (!in_array($value, $countries_all))
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
		preg_match_all("/\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/", $_POST['ip_list'], $ip_list);

		// Count occurrences before dedup — repeat appearances are a meaningful threat signal
		// (an IP hammering your SSH 400 times ranks higher than one that appeared once).
		// array_count_values produces [ip => count]; slicing the map preserves the 10K cap
		// on unique IPs; then private ranges are stripped from the keyset.
		function test_local($ip) {
			return !preg_match('/^(127\.|192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.|::1$)/', $ip);
		}
		$ip_freq = array_count_values($ip_list[0]);
		$ip_freq = array_slice($ip_freq, 0, 10000, true);
		$ip_freq = array_filter($ip_freq, 'test_local', ARRAY_FILTER_USE_KEY);
		$ip_list = array_keys($ip_freq);
	}

	// Declared outside `if ($con !== null)` so view_token fast-path can use it
	// even after the DB connection is established above.
	$vt_geo_cached = $vt_geo_cached ?? [];

	if ($con !== null) {

	// What're our acceptable countries?
	// $good_countries = array('US','CA');

	$matches_total = 0;
	$filtered_total = 0;
	$no_result_ips = [];
	$totalduration = 0;
	$rows_html = '';

	// For CTA threshold and filter UI
	$scanning_proxy_count = 0;
	$category_counts = ['scanning' => 0, 'cloud' => 0, 'vpn' => 0, 'residential' => 0, 'unknown' => 0];
	$country_counts = [];
	// For ip_list_json stored at token creation (Phase A)
	$ip_classified_data = [];
	// For geo_results_json cache (view_token fast path)
	$geo_results_data = [];

	// view_token fast path: serve from geo_results_json cache if available
	$geo_loop_needed = true;
	if ($view_token_mode && !empty($vt_geo_cached)) {
		$geo_loop_needed = false;
		foreach ($vt_geo_cached as $entry) {
			$ip           = $entry['ip'] ?? '';
			$country_code = $entry['country'] ?? '';
			$category     = $entry['classification'] ?? 'unknown';
			$asn_num      = ltrim($entry['asn'] ?? '', 'AS');
			$asn_org      = $entry['asn_org'] ?? '';

			$matches_total++;
			$category_counts[$category] = ($category_counts[$category] ?? 0) + 1;
			if ($category === 'scanning' || $category === 'vpn') $scanning_proxy_count++;
			if ($country_code !== '') $country_counts[$country_code] = ($country_counts[$country_code] ?? 0) + 1;

			$rows_html .= '<tr data-category="'.htmlspecialchars($category, ENT_QUOTES, 'UTF-8').'" data-country="'.htmlspecialchars($country_code, ENT_QUOTES, 'UTF-8').'">';
			$rows_html .= '<td>'.htmlspecialchars($ip, ENT_QUOTES, 'UTF-8').'</td>';
			$rows_html .= '<td><abbr title="'.htmlspecialchars($entry['country_name'] ?? '', ENT_QUOTES, 'UTF-8').'">'.htmlspecialchars($country_code, ENT_QUOTES, 'UTF-8').'</abbr></td>';
			$rows_html .= '<td class="cell-region">'.htmlspecialchars($entry['region'] ?? '', ENT_QUOTES, 'UTF-8').'</td>';
			$rows_html .= '<td class="cell-city">'.htmlspecialchars($entry['city'] ?? '', ENT_QUOTES, 'UTF-8').'</td>';
			$rows_html .= '<td>'.htmlspecialchars($entry['asn'] ?? '', ENT_QUOTES, 'UTF-8').'</td>';
			$rows_html .= '<td class="cell-asn-org" title="'.htmlspecialchars($asn_org, ENT_QUOTES, 'UTF-8').'">'.htmlspecialchars($asn_org, ENT_QUOTES, 'UTF-8').'</td>';
			$rows_html .= '<td class="asn-category asn-category--'.htmlspecialchars($category, ENT_QUOTES, 'UTF-8').'">'.htmlspecialchars($category, ENT_QUOTES, 'UTF-8').'</td>';
			$rows_html .= '</tr>';
		}
		arsort($country_counts);
	}

	if ($geo_loop_needed) {
	foreach ($ip_list as $key => $ip) {
		$ip = mysqli_real_escape_string($con, $ip);
		$ip_int = ipToLong($ip);
		$query = 'SELECT loc.country_iso_code, loc.country_name, loc.subdivision_1_name, loc.city_name,
			asn_net.autonomous_system_number, asn_net.autonomous_system_org
		FROM (
			SELECT geoname_id, network_end_integer
			FROM geoip2_network_current_int
			WHERE ' . $ip_int . ' >= network_start_integer
			ORDER BY network_start_integer DESC LIMIT 1
		) city_net
		LEFT JOIN geoip2_location_current loc
			ON (city_net.geoname_id = loc.geoname_id AND loc.locale_code = "en")
		LEFT JOIN (
			SELECT autonomous_system_number, autonomous_system_org
			FROM geoip2_asn_current_int
			WHERE ' . $ip_int . ' >= network_start_integer
			ORDER BY network_start_integer DESC LIMIT 1
		) asn_net ON 1=1
		WHERE ' . $ip_int . ' <= city_net.network_end_integer';
		$starttime = microtime(true);
		$result = mysqli_query($con, $query);
		$totalduration += microtime(true) - $starttime;
		$geo_found = false;
		while ($row = mysqli_fetch_assoc($result))
		{
			$geo_found = true;
			$asn_num = $row['autonomous_system_number'] ?? '';
			$asn_org = $row['autonomous_system_org'] ?? '';
			$category = classify_asn((string)$asn_num, (string)$asn_org);
			$country_code = $row['country_iso_code'] ?? '';
			if (!in_array($country_code, $good_countries))
			{
				$matches_total++;
				$category_counts[$category]++;
				if ($category === 'scanning' || $category === 'vpn') {
					$scanning_proxy_count++;
				}
				if ($country_code !== '') {
					$country_counts[$country_code] = ($country_counts[$country_code] ?? 0) + 1;
				}
				$ip_classified_data[] = [
					'ip'             => $ip,
					'asn'            => $asn_num !== '' ? 'AS' . $asn_num : '',
					'asn_org'        => $asn_org,
					'classification' => $category,
					'country'        => $country_code,
					'freq'           => $ip_freq[$ip] ?? 1,
				];
				$geo_results_data[] = [
					'ip'             => $ip,
					'country'        => $country_code,
					'country_name'   => $row['country_name'] ?? '',
					'region'         => $row['subdivision_1_name'] ?? '',
					'city'           => $row['city_name'] ?? '',
					'asn'            => $asn_num !== '' ? 'AS' . $asn_num : '',
					'asn_org'        => $asn_org,
					'classification' => $category,
					'freq'           => $ip_freq[$ip] ?? 1,
				];
				$rows_html .= '<tr data-category="'.htmlspecialchars($category, ENT_QUOTES, 'UTF-8').'" data-country="'.htmlspecialchars($country_code, ENT_QUOTES, 'UTF-8').'">';
				$rows_html .= '<td>'.htmlspecialchars($ip, ENT_QUOTES, 'UTF-8').'</td>';
				$rows_html .= '<td><abbr title="'.htmlspecialchars($row['country_name'] ?? '', ENT_QUOTES, 'UTF-8').'">'.htmlspecialchars($country_code, ENT_QUOTES, 'UTF-8').'</abbr></td>';
				$rows_html .= '<td class="cell-region">'.htmlspecialchars($row['subdivision_1_name'] ?? '', ENT_QUOTES, 'UTF-8').'</td>';
				$rows_html .= '<td class="cell-city">'.htmlspecialchars($row['city_name'] ?? '', ENT_QUOTES, 'UTF-8').'</td>';
				$rows_html .= '<td>'.htmlspecialchars($asn_num !== '' ? 'AS'.$asn_num : '', ENT_QUOTES, 'UTF-8').'</td>';
				$rows_html .= '<td class="cell-asn-org" title="'.htmlspecialchars($asn_org, ENT_QUOTES, 'UTF-8').'">'.htmlspecialchars($asn_org, ENT_QUOTES, 'UTF-8').'</td>';
				$rows_html .= '<td class="asn-category asn-category--'.htmlspecialchars($category, ENT_QUOTES, 'UTF-8').'">'.htmlspecialchars($category, ENT_QUOTES, 'UTF-8').'</td>';
				$rows_html .= '</tr>';
			} else {
				$filtered_total++;
			}
		}
		if (!$geo_found) $no_result_ips[] = $ip;
	} // end foreach geo query loop
	} // end if ($geo_loop_needed)

	// Write classification to short-lived cache so get-report.php can skip re-queries.
	// Cache key = SHA-256 of sorted classified IPs. Best-effort: never fail the page load.
	if (!empty($ip_classified_data)) {
		$_cache_ips = array_column($ip_classified_data, 'ip');
		sort($_cache_ips);
		$_geo_cache_key  = hash('sha256', implode(',', $_cache_ips));
		$_geo_ip_json    = json_encode($ip_classified_data);
		$_geo_res_json   = json_encode($geo_results_data);
		$_geo_cache_stmt = $con->prepare(
			'INSERT INTO geo_classification_cache (cache_key, ip_list_json, geo_json, expires_at)
			 VALUES (?, ?, ?, DATE_ADD(NOW(), INTERVAL 30 MINUTE))
			 ON DUPLICATE KEY UPDATE
			   ip_list_json = VALUES(ip_list_json),
			   geo_json     = VALUES(geo_json),
			   expires_at   = DATE_ADD(NOW(), INTERVAL 30 MINUTE)'
		);
		if ($_geo_cache_stmt) {
			$_geo_cache_stmt->bind_param('sss', $_geo_cache_key, $_geo_ip_json, $_geo_res_json);
			$_geo_cache_stmt->execute();
			$_geo_cache_stmt->close();
			$con->query('DELETE FROM geo_classification_cache WHERE expires_at < NOW()');
		}
	}

	// --- CTA threshold & verdict ---
	// "Non-residential" = confirmed scanners/VPNs + cloud/VPS egress.
	// Cloud IPs hitting your infrastructure at volume is itself suspicious,
	// so both categories count toward the CTA trigger.
	$non_residential_count = $scanning_proxy_count + $category_counts['cloud'];
	$non_residential_pct   = $matches_total > 0 ? $non_residential_count / $matches_total : 0;
	$scanning_proxy_pct    = $matches_total > 0 ? $scanning_proxy_count / $matches_total : 0;
	$scanning_pct          = $matches_total > 0 ? round($scanning_proxy_pct * 100) : 0;

	$show_cta = $matches_total >= 5 && (
		$scanning_proxy_count >= 3 ||
		$non_residential_pct >= 0.15
	);

	// Verdict: two independent axes — absolute count and concentration.
	//
	// HIGH:     >=250 confirmed scanners (volume)
	//           OR >=60% scanning AND >=20 scanners (concentration)
	//           OR >=80% scanning (overwhelming)
	// LOW:      <10 confirmed scanners
	//           OR <5% scanning AND <25 scanners (dilute noise)
	//           ...unless cloud volume is substantial (cloud floor: upgrade to MODERATE)
	// MODERATE: everything else
	$cloud_count = $category_counts['cloud'];
	$cloud_pct   = $matches_total > 0 ? $cloud_count / $matches_total : 0;

	if ($matches_total > 0 && (
		$scanning_proxy_count >= 250
		|| ($scanning_proxy_pct >= 0.60 && $scanning_proxy_count >= 20)
		|| $scanning_proxy_pct >= 0.80
	)) {
		$verdict_level = 'HIGH';
	} elseif ($matches_total > 0 && (
		$scanning_proxy_count < 10
		|| ($scanning_proxy_pct < 0.05 && $scanning_proxy_count < 25)
	)) {
		// Cloud floor: significant cloud IPs upgrade LOW → MODERATE
		if ($cloud_count >= 50 || $cloud_pct >= 0.15) {
			$verdict_level = 'MODERATE';
		} else {
			$verdict_level = 'LOW';
		}
	} else {
		$verdict_level = 'MODERATE';
	}

	// Suppress CTA for LOW verdict — avoids "LOW THREAT + buy report" contradiction
	if ($verdict_level === 'LOW') {
		$show_cta = false;
	}

	// One-sentence reason explaining what triggered the verdict
	if ($verdict_level === 'HIGH') {
		if ($scanning_proxy_count >= 250 && $scanning_proxy_pct < 0.60) {
			$verdict_reason = $scanning_proxy_count . ' confirmed scanners/proxies detected.';
		} else {
			$verdict_reason = $scanning_pct . '% of IPs are confirmed scanning or proxy infrastructure.';
		}
	} elseif ($verdict_level === 'MODERATE') {
		if ($scanning_proxy_count < 10 && ($cloud_count >= 50 || $cloud_pct >= 0.15)) {
			$verdict_reason = $cloud_count . ' cloud infrastructure IPs detected — may indicate botnet use or compromised VMs.';
		} else {
			$verdict_reason = $scanning_proxy_count . ' confirmed scanner' . ($scanning_proxy_count === 1 ? '' : 's') . '/proxies detected (' . $scanning_pct . '% of total).';
		}
	} else {
		$verdict_reason = '';
	}

	arsort($country_counts);

	// --- Output results section ---
	echo '<section id="results" class="wrapper style4 fade-up"><div class="inner">';
	echo '<h2 id="result">Lookup Results</h2>';
	// In view_token mode the page is server-rendered (not injected by AJAX), so
	// we need a script to scroll to results. The #results hash in the link from
	// report.php handles the common case; this handles direct URL access without hash.
	if ($view_token_mode): ?>
	<script>if(!location.hash)document.getElementById('results').scrollIntoView({behavior:'smooth'});</script>
	<?php endif;

	// --- Threat CTA (above filter + table) ---
	if ($show_cta && !$view_token_mode): ?>
	<div id="threat-cta" class="threat-cta-box threat-cta-box--<?php echo htmlspecialchars(strtolower($verdict_level), ENT_QUOTES, 'UTF-8'); ?>" role="region" aria-label="Threat Assessment">
		<div class="threat-cta-left">
			<p class="asn-verdict asn-verdict--<?php echo htmlspecialchars(strtolower($verdict_level), ENT_QUOTES, 'UTF-8'); ?>">
				<?php echo htmlspecialchars($verdict_level, ENT_QUOTES, 'UTF-8'); ?> THREAT
			</p>
			<?php if ($verdict_reason !== ''): ?>
			<p class="threat-cta-reason"><?php echo htmlspecialchars($verdict_reason, ENT_QUOTES, 'UTF-8'); ?></p>
			<?php endif; ?>
			<p class="threat-cta-stats"><?php echo round($non_residential_pct * 100); ?>% of IPs from cloud, scanning, or proxy infrastructure
				(<?php echo $non_residential_count; ?> of <?php echo $matches_total; ?> IPs)</p>
		</div>
		<div class="threat-cta-right">
			<form method="POST" action="/get-report.php" id="cta-form">
				<input type="hidden" name="ip_classified_json" id="ip-classified-json"
					value="<?php echo htmlspecialchars(json_encode($ip_classified_data), ENT_QUOTES, 'UTF-8'); ?>" />
				<input type="hidden" name="tier" value="free">
				<?php if (($_GET['error'] ?? '') === 'rate_limit'): ?>
				<p class="threat-cta-error" style="color:#e07070;margin:0 0 0.6em;font-size:0.9em">Too many free reports generated. Try again in an hour.</p>
				<?php endif; ?>
				<ul class="threat-cta-features">
					<li>Geo + ASN breakdown of your top 25 IPs</li>
					<li>Shareable link &mdash; send to your team now</li>
					<li>Saved 7 days free &nbsp;&middot;&nbsp; $9 for full threat scores + permanent link</li>
				</ul>
				<button type="submit" id="cta-button" class="button">Get Free Threat Report</button>
				<p class="threat-cta-fine">No account. No payment. Takes 5 seconds.
					&nbsp;&middot;&nbsp;<a href="/report.php?token=00000000-0000-0000-0000-000000000000" target="_blank">See what $9 unlocks &rarr;</a></p>
			</form>
		</div>
	</div>
	<?php elseif ($view_token_mode): ?>
	<p style="margin:0 0 1.5em">
		<a href="/report.php?token=<?php echo htmlspecialchars($view_token_val, ENT_QUOTES, 'UTF-8'); ?>" class="button small alt">&#8592; Back to your report</a>
	</p>
	<?php endif;

	// --- Filter & Export (above table) ---
	echo '<div id="filter-export" role="region" aria-label="Filter and Export">';
	echo '<details id="filter-details" open>';
	echo '<summary id="filter-summary">Filter &amp; Export &mdash; Showing <span id="filter-count">'.$matches_total.'</span> of <span id="filter-total">'.$matches_total.'</span> IPs</summary>';
	echo '<div id="filter-layout">';

	// Left column: action buttons + firewall rules output
	echo '<div id="filter-left">';

	// Row 1: primary export actions
	echo '<div id="action-buttons-primary">';
	echo '<button id="download-csv" class="button small">&#8595; Download CSV</button>';
	if (!empty($no_result_ips)) {
		$n = count($no_result_ips);
		echo '<button id="toggle-unresolved" class="button small alt">Show '.$n.' unresolved IP'.($n !== 1 ? 's' : '').'</button>';
	}
	echo '</div>';

	// Row 2: firewall rule generators
	echo '<div id="export-buttons">';
	echo '<button class="button small" id="show-iptables">Show iptables rules</button>';
	echo '<button class="button small" id="show-ufw">Show ufw rules</button>';
	echo '<button class="button small" id="show-nginx">Show nginx block</button>';
	echo '</div>';

	// Firewall rule output (shown on demand)
	echo '<div id="rules-iptables" class="rules-block" style="display:none" aria-label="iptables block rules"><button class="button small copy-rules" data-target="rules-iptables-pre">Copy</button><pre id="rules-iptables-pre"></pre></div>';
	echo '<div id="rules-ufw"      class="rules-block" style="display:none" aria-label="ufw deny rules"><button class="button small copy-rules" data-target="rules-ufw-pre">Copy</button><pre id="rules-ufw-pre"></pre></div>';
	echo '<div id="rules-nginx"    class="rules-block" style="display:none" aria-label="nginx geo block"><button class="button small copy-rules" data-target="rules-nginx-pre">Copy</button><pre id="rules-nginx-pre"></pre></div>';

	echo '<p style="margin:0.8em 0 0;font-size:0.85em;opacity:0.7">Block known scanners reported by the ip2geo community &mdash; <a href="/intel.php" target="_blank" rel="noopener noreferrer">Community Block List <i class="fas fa-external-link-alt" style="font-size:0.7em;opacity:0.6;vertical-align:middle"></i></a></p>';

	echo '</div>'; // end #filter-left

	// Right column: filter chips
	echo '<div id="filter-right">';

	// ASN category chips (leftmost — highest signal)
	$cat_labels = ['scanning' => 'Scanning', 'cloud' => 'Cloud exit', 'vpn' => 'VPN/Proxy', 'residential' => 'Residential', 'unknown' => 'Unknown'];
	echo '<div id="filter-categories">';
	echo '<strong>ASN Categories</strong>';
	foreach ($cat_labels as $cat => $cat_label) {
		if (($category_counts[$cat] ?? 0) === 0) continue;
		$cat_safe = htmlspecialchars($cat, ENT_QUOTES, 'UTF-8');
		echo '<label class="cat-'.$cat_safe.'"><input type="checkbox" class="filter-category" value="'.$cat_safe.'" checked><span class="chip-label">'.$cat_label.'</span> <span class="chip-count">('.$category_counts[$cat].')</span></label>';
	}
	echo '</div>';

	// Country chips
	echo '<div id="filter-countries">';
	echo '<strong>Countries <span class="chip-hint">⇧ multi-select</span></strong>';
	echo '<div class="filter-chips">';
	foreach ($country_counts as $cc => $count) {
		$cc_safe = htmlspecialchars($cc, ENT_QUOTES, 'UTF-8');
		echo '<label><input type="checkbox" class="filter-country" value="'.$cc_safe.'" checked><span class="chip-label">'.$cc_safe.'</span> <span class="chip-count">('.$count.')</span></label>';
	}
	echo '</div>';
	echo '</div>';

	echo '</div>'; // end #filter-right
	echo '</div>'; // end #filter-layout
	echo '</details></div>'; // end #filter-details, #filter-export

	// --- Results table ---
	echo '<div class="table-wrapper" style="overflow-x:auto">';

	echo '<table id="results-table"><thead><tr>';
	echo '<th scope="col">IP</th>';
	echo '<th scope="col"><abbr title="Country Code">CC</abbr></th><th scope="col" class="cell-region">State/Province</th><th scope="col" class="cell-city">City</th>';
	echo '<th scope="col">ASN</th><th scope="col" class="cell-asn-org">ASN Org</th><th scope="col">Category</th>';
	echo '</tr></thead><tbody>';
	echo $rows_html;
	echo '</tbody>';

	if (!empty($no_result_ips)) {
		echo '<tbody id="unresolved-rows" style="display:none">';
		foreach ($no_result_ips as $unresolved_ip) {
			echo '<tr><td>'.htmlspecialchars($unresolved_ip, ENT_QUOTES, 'UTF-8').'</td><td></td><td></td><td></td><td></td><td></td><td></td></tr>';
		}
		echo '</tbody>';
	}
	echo '</table>';

	// Empty filter state (shown by JS when all rows filtered out)
	echo '<p id="empty-filter-msg" style="display:none;text-align:center;padding:1em;opacity:0.7">No IPs match the current filter. Try selecting more categories.</p>';

	echo '</div>';

	// --- Summary stats ---
	$submitted = count($ip_list);
	echo '<table id="stats-table" style="font-family:monospace;font-size:0.8em;border-collapse:collapse;margin-top:0.5em;width:auto">';
	echo '<tr><td>'.$submitted.'</td><td>IP'.($submitted !== 1 ? 's' : '').' submitted (valid, unique, non-private)</td></tr>';
	echo '<tr><td>'.$matches_total.'</td><td>returned geo results</td></tr>';
	if ($filtered_total > 0) {
		echo '<tr><td>'.$filtered_total.'</td><td>excluded by country filter</td></tr>';
	}
	echo '<tr><td>'.count($no_result_ips).'</td><td>returned no geo data</td></tr>';
	echo '<tr><td>'.round($totalduration,3).'s</td><td>query duration</td></tr>';
	if (!empty($good_countries)) {
		echo '<tr><td>—</td><td>excluded countries: '.htmlspecialchars(implode(' ', $good_countries)).'</td></tr>';
	}
	echo '</table>';

	echo '</div></section>';

	} // end if ($con !== null)
}
else
{
	echo '<!--';
	//echo '<iframe src="/about.php" style="" />';
	echo '-->';
}

?>


				<!-- Threat Reports -->
				<section id="reports" class="wrapper style1 fade-up">
					<div class="inner">
						<h2>Threat Reports</h2>
						<p>When a lookup reveals a high proportion of scanning, cloud, or proxy infrastructure, ip2geo generates a threat report — free instantly, or with full AbuseIPDB threat scores and firewall scripts for $9.</p>
						<div class="row">
							<div class="col-6 col-12-medium">
								<h3>Free report</h3>
								<ul>
									<li><strong>Geo + ASN breakdown</strong> of your top 25 IPs</li>
									<li><strong>Shareable link</strong> — send to your team, saved for 7 days</li>
								</ul>
								<h3>Full report — $9 one-time</h3>
								<ul>
									<li><strong>AbuseIPDB reputation scores</strong> for your top 25 IPs: see which ones are confirmed attackers</li>
									<li><strong>ASN CIDR ranges</strong> for resilient blocking: block entire scanning networks, not just individual IPs that rotate</li>
									<li><strong>Ready-to-run firewall scripts</strong> for iptables, ufw, and nginx</li>
									<li><strong>Community intel</strong> (opt-in): see how many other ip2geo users reported the same IPs this week, with trend indicators showing whether activity is escalating</li>
									<li><strong>Permanent link</strong> — no expiry, come back any time</li>
								</ul>
							</div>
							<div class="col-6 col-12-medium">
								<h3>See it in action</h3>
								<p>The sample below is a full $9 report using real Tor exit node data with live AbuseIPDB enrichment — so you can see exactly what you get before deciding to upgrade.</p>
								<p style="text-align:right"><a href="/report.php?token=00000000-0000-0000-0000-000000000000" target="_blank" class="button">See a sample full report &rarr;</a></p>
							</div>
						</div>
					</div>
				</section>


				<!-- Contact / Contribute -->
				<section id="contribute" class="wrapper style4 fade-up">
					<div class="inner">
						<h2>Contact / Contribute</h2>
						<p>ip2geo.org is maintained and run by me, Josh. Hi. If this tool was helpful, feel free to say hello &mdash; or help cover hosting costs if the free tools saved the day.</p>
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
										</ul>
									</li>
								</ul>
							</div>
						</div>
					</div>
				</section>


				<!-- About -->
				<section id="about" class="wrapper style1 fade-up">
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
							<h3>What It's Grown Into</h3>
							<p>The free lookup is still here. But over time, ip2geo.org has grown into something more complete. When a lookup shows a high concentration of scanning or proxy infrastructure, you can now generate a <strong>Threat Report</strong> — free instantly (geo and ASN breakdown, 7-day shareable link), or upgrade for $9 to add AbuseIPDB threat scores, ASN CIDR ranges, and ready-to-run firewall scripts for iptables, ufw, and nginx.</p>
							<p>There's also a <a href="/intel.php">Community Block List</a> — a rolling 7-day feed of CIDR ranges reported by opted-in ip2geo users. If you contribute your report, your data joins the aggregate anonymously. If you just want the list, download it and apply it directly to your firewall.</p>
							<h3>How It Works</h3>
							<p>Paste any block of text. ip2geo.org scans it for IPv4 addresses, checks them against a geolocation database, and returns results you can filter by country or infrastructure category — scanning ranges, cloud exit nodes, VPN and proxy infrastructure, or residential traffic. Want to only see scanning infrastructure hits from outside the US? Done. Focus only on what matters.</p>
							<h3>Why It's Free</h3>
							<p>This tool was built using free and open-source resources, and it's free because I wish something like this had existed when I needed it most. If it helps you too, consider <a href="https://www.buymeacoffee.com/ip2geo" target="_blank">buying me a coffee</a> or tossing a few bucks toward hosting costs.</p>
						</section>
					</div>
				</section>

			</div>

		<?php require __DIR__ . '/includes/footer.php'; ?>

		<!-- Scripts -->
		<script data-cfasync="false">
		(function() {
			var form = document.getElementById('iplookup');
			if (!form) return;
			var btn = form.querySelector('input[type="submit"]');
			if (!btn) return;
			btn.addEventListener('click', async function(e) {
				e.preventDefault();
				e.stopPropagation();

				var raw = document.getElementById('message').value;
				var matches = raw.match(/\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g);
				var count = matches ? matches.length : 0;

				var overlay = document.createElement('div');
				overlay.style.cssText = 'position:fixed;top:0;left:0;width:100vw;height:100vh;background:linear-gradient(to right,rgba(94,66,166,0.97),rgba(183,78,145,0.97));display:flex;align-items:center;justify-content:center;z-index:2147483647;';
				var msg = document.createElement('div');
				msg.style.cssText = 'font-family:monospace;font-size:1.1em;color:#fff;letter-spacing:0.05em;opacity:0.9;';
				msg.textContent = 'Processing ' + count.toLocaleString() + ' IP' + (count !== 1 ? 's' : '') + ' ';
				var dotSpan = document.createElement('span');
				dotSpan.style.cssText = 'display:inline-block;width:1.8em;text-align:left;';
				var dots = ['.', '..', '...'];
				var dotIdx = 0;
				dotSpan.textContent = dots[dotIdx];
				msg.appendChild(dotSpan);
				var dotTimer = setInterval(function() {
					dotIdx = (dotIdx + 1) % dots.length;
					dotSpan.textContent = dots[dotIdx];
				}, 400);
				overlay.appendChild(msg);
				document.body.appendChild(overlay);

				var cleanup = function() {
					clearInterval(dotTimer);
					overlay.remove();
				};

				try {
					var resp = await fetch(window.location.pathname, {
						method: 'POST',
						body: new FormData(form)
					});
					if (!resp.ok) throw new Error('HTTP ' + resp.status);
					var html = await resp.text();
					var doc = new DOMParser().parseFromString(html, 'text/html');
					var newResults = doc.getElementById('results');
					if (!newResults) throw new Error('no results section in response');

					var existing = document.getElementById('results');
					if (existing) {
						existing.outerHTML = newResults.outerHTML;
					} else {
						document.getElementById('intro').insertAdjacentHTML('afterend', newResults.outerHTML);
					}
					var inserted = document.getElementById('results');
					cleanup();
					if (inserted) inserted.scrollIntoView({ behavior: 'smooth' });

					var bucket = count === 1 ? '1'
					             : count <= 10   ? '2-10'
					             : count <= 50   ? '11-50'
					             : count <= 100  ? '51-100'
					             : count <= 500  ? '101-500'
					             : count <= 1000 ? '501-1000'
					             : count <= 5000 ? '1001-5000'
					             :                 '5000+';
					try { umami.track('lookup_submit', { ip_count_bucket: bucket }); } catch(_) {}

				} catch (err) {
					cleanup();
					HTMLFormElement.prototype.submit.call(form);
				}
			});
		// CSV download (delegated — works after AJAX injection)
		document.addEventListener('click', function(e) {
			if (e.target.id !== 'download-csv') return;
			try { umami.track('download_csv'); } catch(_) {}
			var bom = '\uFEFF';
			var headers = ['IP','CC','State/Province','City','ASN','ASN Org','Category'];
			var rows = [headers];
			document.querySelectorAll('#results-table tbody tr').forEach(function(tr) {
				if (tr.parentElement.style.display === 'none') return;
				if (tr.classList.contains('row-hidden')) return;
				var row = [];
				tr.querySelectorAll('td').forEach(function(td) {
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

		// Toggle unresolved rows — handler moved to ip2geo-app.js so it can call applyFilters()

		})();
		</script>
			<script src="assets/js/jquery.min.js"></script>
			<script src="assets/js/jquery.scrollex.min.js"></script>
			<script src="assets/js/jquery.scrolly.min.js"></script>
			<script src="assets/js/browser.min.js"></script>
			<script src="assets/js/breakpoints.min.js"></script>
			<script src="assets/js/util.js"></script>
			<script src="assets/js/main.js"></script>
		<script src="assets/js/ip2geo-app.js"></script>

	</body>
</html>
