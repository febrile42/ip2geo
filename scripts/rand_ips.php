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

$ips = [];
while (count($ips) < $no) {
    $n = random_int(0, 4294967295);
    if (is_public($n, $reserved)) {
        $ips[] = long2ip($n);
    }
}

echo implode(' ', $ips);
?>
</body>
</html>
