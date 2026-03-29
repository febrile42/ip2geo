<?php
// Single source of truth for the site footer.
// Included from page-level scope and from inside render_page_close() (function scope),
// so $db_data_date is accessed via $GLOBALS to work correctly in both contexts.
defined('APP_VERSION') || define('APP_VERSION', '2.6.3');
$_footer_data_date = $GLOBALS['db_data_date'] ?? null;
?>
<!-- Footer -->
<footer id="footer" class="wrapper style1-alt">
    <div class="inner">
        <ul class="menu">
            <li>This product includes GeoLite2 data created by MaxMind, available from <a href="http://www.maxmind.com" target="_blank">http://www.maxmind.com</a>.</li>
        </ul>
        <ul class="menu">
            <li><a href="/changelog.php">v<?php echo APP_VERSION; ?></a> &ndash; &copy;<?php echo date('Y'); ?></li>
            <?php if ($_footer_data_date): ?><li>Data: <?php echo htmlspecialchars((string)$_footer_data_date, ENT_QUOTES, 'UTF-8'); ?></li><?php endif; ?>
            <li><a href="/privacy.php">Privacy Policy</a></li>
            <li>Design: <a href="http://html5up.net" target="_blank">HTML5 UP</a></li>
        </ul>
    </div>
</footer>
