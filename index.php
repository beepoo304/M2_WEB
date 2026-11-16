<?php
// Strona główna przez PHP, żeby przeglądarka zawsze pobierała aktualny index.html (hosting nie ma mod_headers).
header('Content-Type: text/html; charset=utf-8');
header('Cache-Control: no-cache, must-revalidate');
readfile(__DIR__ . '/index.html');
