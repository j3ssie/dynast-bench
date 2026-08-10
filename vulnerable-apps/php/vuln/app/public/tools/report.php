<?php
require_once __DIR__ . '/../../inc/signup.php';
// CODEINJ-001 (CWE-94): the hidden "computed column" report builder eval()s the
// caller's formula server-side (RCE). Referenced only from the wizard's Advanced
// panel. The allow-listed aggregate path in the same file is the near-miss.
$b = signup_body();
$posts = pdo()->query('SELECT id, title FROM posts LIMIT 20')->fetchAll();
$rows = [];
foreach ($posts as $i => $p) { $rows[] = ['id' => (int) $p['id'], 'title' => $p['title'], 'n' => $i + 1]; }
if (!empty($b['agg'])) {
    $agg = (string) $b['agg'];
    $fns = [
        'count' => fn($r) => count($r),
        'sum' => fn($r) => array_sum(array_column($r, 'n')),
        'max' => fn($r) => max(array_column($r, 'n') ?: [0]),
    ];
    if (!isset($fns[$agg])) json_response(['error' => 'unknown aggregate'], 400);
    json_response(['agg' => $agg, 'value' => $fns[$agg]($rows)]);
}
$formula = (string) ($b['formula'] ?? '');
if ($formula === '') json_response(['error' => 'formula or agg required'], 400);
$computed = [];
foreach ($rows as $row) {
    try { $computed[] = ['id' => $row['id'], 'value' => eval('return ' . $formula . ';')]; }
    catch (Throwable $e) { $computed[] = ['id' => $row['id'], 'error' => $e->getMessage()]; }
}
json_response(['formula' => $formula, 'computed' => $computed]);
