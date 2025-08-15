#!/usr/bin/env php
<?php
/**
 * Quick Apache/Nginx access log analyzer (combined format).
 * Usage: php scripts/php/cli/apache_nginx_log_report.php /var/log/nginx/access.log
 */
if ($argc < 2) {
    fwrite(STDERR, "Usage: php ".$argv[0]." <access_log>\n");
    exit(1);
}
$path = $argv[1];
if (!file_exists($path)) {
    fwrite(STDERR, "File not found: $path\n");
    exit(1);
}
$ips = [];
$codes = [];
$ua = [];
$fh = fopen($path, "r");
if (!$fh) exit(1);
while (($line = fgets($fh)) !== false) {
    if (preg_match('/^(\S+) \S+ \S+ \[(.*?)\] "(.*?)" (\d{3}) (\S+) "(.*?)" "(.*?)"/', $line, $m)) {
        $ip = $m[1]; $status = $m[4]; $userAgent = $m[7];
        $ips[$ip] = ($ips[$ip] ?? 0) + 1;
        $codes[$status] = ($codes[$status] ?? 0) + 1;
        $ua[$userAgent] = ($ua[$userAgent] ?? 0) + 1;
    }
}
fclose($fh);
arsort($ips); arsort($codes); arsort($ua);
echo "Top IPs:\n"; foreach(array_slice($ips,0,10,true) as $k=>$v) echo "$k $v\n";
echo "\nStatus codes:\n"; foreach($codes as $k=>$v) echo "$k $v\n";
echo "\nTop User-Agents:\n"; foreach(array_slice($ua,0,10,true) as $k=>$v) echo "$k $v\n";
