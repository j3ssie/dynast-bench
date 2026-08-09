<?php
require_once __DIR__ . '/bootstrap.php';
const DB_HOST = 'mysql';
const DB_NAME = 'bench';
const DB_USER = 'bench';
const DB_PASS = 'bench';
function pdo(): PDO {
    static $pdo = null;
    if ($pdo === null) {
        $host = getenv('DB_HOST') ?: DB_HOST;
        $name = getenv('DB_NAME') ?: DB_NAME;
        $user = DB_USER;
        $pass = DB_PASS;
        $pdo = new PDO("mysql:host=$host;dbname=$name;charset=utf8mb4", $user, $pass, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);
    }
    return $pdo;
}
?>
