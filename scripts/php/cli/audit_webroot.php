#!/usr/bin/env php
<?php
/**
 * Scan a webroot for risky PHP patterns (defensive).
 * Usage: php scripts/php/cli/audit_webroot.php /var/www/html
 */
if ($argc < 2) {
    fwrite(STDERR, "Usage: php ".$argv[0]." <webroot>\n");
    exit(1);
}
$root = $argv[1];
$patterns = [
    'eval(',
    'base64_decode(',
    'shell_exec(',
    'passthru(',
    'system(',
    'popen(',
    'proc_open(',
    'assert(',
    'create_function(',
    'preg_replace(' // e modifier is deprecated but still risky historically
];
$rii = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root));
foreach ($rii as $file) {
    if ($file->isDir()) continue;
    if (strtolower($file->getExtension()) !== 'php') continue;
    $lines = @file($file->getPathname());
    if ($lines === false) continue;
    foreach ($lines as $num => $line) {
        foreach ($patterns as $p) {
            if (stripos($line, $p) !== false) {
                echo $file->getPathname().":".($num+1)." contains '".$p."'\n";
            }
        }
    }
}
