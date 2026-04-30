<?php
// Shared v4 page chrome — used by all user-facing pages.
// Provides render_page_open() and render_page_close() so every page renders
// the same nav, head, theme toggle, smooth-scroll, and footer.

if (!function_exists('render_page_open')):

/**
 * @param string $title       Page <title> + og:title fallback.
 * @param string $meta_desc   Optional meta description override.
 * @param array  $og          Optional Open Graph fields (title, description, url).
 * @param array  $nav_items   Optional custom nav. Each entry: ['label' => '...', 'href' => '...']. Defaults to the marketing nav.
 */
function render_page_open(string $title, string $meta_desc = '', array $og = [], array $nav_items = []): void {
    $safe_title = htmlspecialchars($title, ENT_QUOTES, 'UTF-8');
    $safe_desc  = $meta_desc
        ? htmlspecialchars($meta_desc, ENT_QUOTES, 'UTF-8')
        : 'ip2geo.org — bulk IP geolocation and threat triage.';
    $default_nav = [
        ['label' => 'Lookup',    'href' => '/#lookup'],
        ['label' => 'Block List', 'href' => '/intel.php'],
        ['label' => 'Changelog', 'href' => '/changelog.php'],
    ];
    $nav = $nav_items ?: $default_nav;
    ?>
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <?php if ($_SERVER['HTTP_HOST'] === 'ip2geo.org'): ?>
    <script defer src="https://cloud.umami.is/script.js" data-website-id="656d7a15-6282-4079-af1e-b8ed857fba2e"></script>
    <?php endif; ?>
    <title><?php echo $safe_title; ?></title>
    <meta charset="utf-8" />
    <meta name="description" content="<?php echo $safe_desc; ?>" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <?php if (!empty($og)): ?>
    <meta property="og:title" content="<?php echo htmlspecialchars($og['title'] ?? $title, ENT_QUOTES, 'UTF-8'); ?>">
    <meta property="og:description" content="<?php echo htmlspecialchars($og['description'] ?? $safe_desc, ENT_QUOTES, 'UTF-8'); ?>">
    <meta property="og:url" content="<?php echo htmlspecialchars($og['url'] ?? '', ENT_QUOTES, 'UTF-8'); ?>">
    <meta property="og:image" content="https://ip2geo.org/assets/images/og-card.webp">
    <meta property="og:type" content="website">
    <?php endif; ?>
    <link rel="preconnect" href="https://fonts.bunny.net" crossorigin>
    <link rel="stylesheet" href="https://fonts.bunny.net/css?family=geist:400,500,700,900|geist-mono:400,500&display=swap">
    <link rel="stylesheet" href="/assets/css/ip2geo-app.css" />
    <link rel="stylesheet" href="/assets/css/v4.css" />
    <link rel="stylesheet" href="/assets/css/ip2geo-print.css" media="print" />
    <link rel="icon" href="/favicon.ico" />
    <script>
    // Apply saved theme before paint to avoid a flash. Dark default.
    (function() {
        try {
            var t = localStorage.getItem('ip2geo-theme');
            if (t === 'light' || t === 'dark') {
                document.documentElement.setAttribute('data-theme', t);
            }
        } catch (_) {}
    })();
    </script>
</head>
<body>

    <!-- Top nav -->
    <header class="nav" role="banner">
        <div class="nav-inner">
            <a href="/" class="wordmark" aria-label="ip2geo home">ip2geo</a>
            <nav class="nav-links" aria-label="primary">
                <?php foreach ($nav as $item):
                    $label = htmlspecialchars($item['label'], ENT_QUOTES, 'UTF-8');
                    $href  = htmlspecialchars($item['href'],  ENT_QUOTES, 'UTF-8');
                ?>
                <a href="<?php echo $href; ?>"><?php echo $label; ?></a>
                <?php endforeach; ?>
                <button class="theme-toggle" id="themeToggle" type="button" aria-label="Toggle color theme">
                    <svg class="icon-moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>
                    <svg class="icon-sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"/></svg>
                </button>
            </nav>
        </div>
    </header>

    <main>
    <?php
}

function render_page_close(): void { ?>
    </main>
    <?php require __DIR__ . '/footer.php'; ?>

    <!-- Theme toggle -->
    <script>
    (function() {
        var btn = document.getElementById('themeToggle');
        if (!btn) return;
        btn.addEventListener('click', function() {
            var root = document.documentElement;
            var next = root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
            root.setAttribute('data-theme', next);
            try { localStorage.setItem('ip2geo-theme', next); } catch (_) {}
        });
    })();
    </script>

    <!-- Smooth in-page anchor scroll (fixed ~500ms regardless of distance) -->
    <script>
    (function() {
        var DURATION = 500;
        var OFFSET = 72;
        var reduced = window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches;
        function easeOutCubic(t) { return 1 - Math.pow(1 - t, 3); }
        function scrollTo(targetY) {
            if (reduced) { window.scrollTo(0, targetY); return; }
            var startY = window.pageYOffset;
            var dy = targetY - startY;
            if (dy === 0) return;
            var t0 = performance.now();
            function step(now) {
                var p = Math.min(1, (now - t0) / DURATION);
                window.scrollTo(0, startY + dy * easeOutCubic(p));
                if (p < 1) requestAnimationFrame(step);
            }
            requestAnimationFrame(step);
        }
        document.addEventListener('click', function(e) {
            var a = e.target.closest && e.target.closest('a[href^="#"]');
            if (!a) return;
            var hash = a.getAttribute('href');
            if (!hash || hash === '#') return;
            var target = document.getElementById(hash.slice(1));
            if (!target) return;
            e.preventDefault();
            var y = target.getBoundingClientRect().top + window.pageYOffset - OFFSET;
            scrollTo(y);
            history.replaceState(null, '', hash);
        });
    })();
    </script>
</body>
</html>
    <?php
}

endif;
