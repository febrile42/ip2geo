<html>
<head></head>
<body><?php
$no = isset($_GET['no']) ? max(1, (int)$_GET['no']) : 10000;

// Reserved/private ranges to exclude (mirrors deploy test)
$reserved = [
    ['start' => ip2long('0.0.0.0'),         'end' => ip2long('0.255.255.255')],     // 0.0.0.0/8
    ['start' => ip2long('10.0.0.0'),        'end' => ip2long('10.255.255.255')],    // 10.0.0.0/8
    ['start' => ip2long('100.64.0.0'),      'end' => ip2long('100.127.255.255')],   // 100.64.0.0/10
    ['start' => ip2long('127.0.0.0'),       'end' => ip2long('127.255.255.255')],   // 127.0.0.0/8
    ['start' => ip2long('169.254.0.0'),     'end' => ip2long('169.254.255.255')],   // 169.254.0.0/16
    ['start' => ip2long('172.16.0.0'),      'end' => ip2long('172.31.255.255')],    // 172.16.0.0/12
    ['start' => ip2long('192.168.0.0'),     'end' => ip2long('192.168.255.255')],   // 192.168.0.0/16
    ['start' => ip2long('224.0.0.0'),       'end' => ip2long('239.255.255.255')],   // 224.0.0.0/4 multicast
    ['start' => ip2long('240.0.0.0'),       'end' => ip2long('255.255.255.255')],   // 240.0.0.0/4 reserved
];

function is_public(int $n, array $reserved): bool {
    foreach ($reserved as $r) {
        if ($n >= $r['start'] && $n <= $r['end']) return false;
    }
    return true;
}

// ?pool=X — generate X unique IPs then sample $no total from them (some IPs repeat).
// Realistic: a small number of sources account for most hits.
// Example: ?no=500&pool=50 → 500 entries drawn from 50 unique IPs (~10 hits each on average).
$pool_size = isset($_GET['pool']) ? min(max(1, (int)$_GET['pool']), $no) : 0;

// Build unique IP pool
$target = $pool_size > 0 ? $pool_size : $no;
$pool = [];
while (count($pool) < $target) {
    $n = random_int(0, 4294967295);
    if (is_public($n, $reserved)) {
        $pool[] = long2ip($n);
    }
}

// In clustered mode, sample $no entries from the pool (with replacement) then shuffle
if ($pool_size > 0) {
    $last = $pool_size - 1;
    $ips  = [];
    for ($i = 0; $i < $no; $i++) {
        $ips[] = $pool[random_int(0, $last)];
    }
    shuffle($ips);
} else {
    $ips = $pool;
}

echo implode(' ', $ips);
?>
</body>
</html>
