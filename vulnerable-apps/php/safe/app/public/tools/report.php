<?php
require_once __DIR__ . '/../../inc/signup.php';
// FIXED CODEINJ-001: the "computed column" is resolved through a fixed set of
// named projections instead of being eval'd; an unknown formula is rejected. The
// allow-listed aggregate path in the same file is the near-miss.
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
$columns = [
    "strlen(\$row['title'])" => fn($row) => strlen($row['title']),
    "\$row['n']" => fn($row) => $row['n'],
    "\$row['id']" => fn($row) => $row['id'],
];
if (!isset($columns[$formula])) json_response(['error' => 'unknown column'], 400);
$computed = [];
foreach ($rows as $row) { $computed[] = ['id' => $row['id'], 'value' => $columns[$formula]($row)]; }
json_response(['formula' => $formula, 'computed' => $computed]);
