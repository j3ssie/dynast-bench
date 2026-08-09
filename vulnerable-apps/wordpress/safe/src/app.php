<?php
// BenchPress Tasks: WordPress-compatible patched twin.
// Same plugin shape as vuln/, with YAML-named sinks fixed.

class BenchWpdb {
    public function query($sql) { return $sql; }
    public function prepare($sql, ...$args) {
        foreach ($args as $arg) {
            $safe = is_numeric($arg) ? (string)$arg : "'" . str_replace("'", "''", (string)$arg) . "'";
            $sql = preg_replace('/%[sd]/', $safe, $sql, 1);
        }
        return $sql;
    }
}
$wpdb = new BenchWpdb();

class BenchTaskImportGadget {
    public $command = '';
    public function __wakeup() {
        $GLOBALS['bench_unserialize_result'] = 'gadget-ran:' . $this->command;
    }
}

function bench_variant() { return getenv('VARIANT') ?: 'safe'; }
function bench_state_path() { return '/tmp/benchpress-state-' . bench_variant() . '.json'; }
function bench_seed_state() {
    return [
        'users' => [
            ['id'=>1,'username'=>'admin','email'=>'admin@bench.local','password'=>'Admin123!','role'=>'admin','org'=>'acme','verified'=>true],
            ['id'=>2,'username'=>'editor','email'=>'editor@bench.local','password'=>'Editor123!','role'=>'editor','org'=>'acme','verified'=>true],
            ['id'=>3,'username'=>'user1','email'=>'user1@bench.local','password'=>'User123!','role'=>'user','org'=>'acme','verified'=>true],
            ['id'=>4,'username'=>'user2','email'=>'user2@bench.local','password'=>'User123!','role'=>'user','org'=>'globex','verified'=>true],
            ['id'=>5,'username'=>'service','email'=>'service@bench.local','password'=>'admin','role'=>'service','org'=>'acme','verified'=>true]
        ],
        'tasks' => [
            ['id'=>101,'slug'=>'acme-public','title'=>'Acme public launch','body'=>'Published Acme task','status'=>'published','org'=>'acme','author'=>'user1@bench.local'],
            ['id'=>102,'slug'=>'acme-private','title'=>'Acme private draft','body'=>'Acme private planning','status'=>'draft','org'=>'acme','author'=>'editor@bench.local'],
            ['id'=>201,'slug'=>'globex-internal','title'=>'Globex confidential draft','body'=>'GLOBEX-CONFIDENTIAL-MARKER-7f3a <script>window.BENCH_STORED_XSS=1</script>','status'=>'draft','org'=>'globex','author'=>'user2@bench.local']
        ],
        'options' => [
            'webhook_url' => 'https://hooks.invalid/acme',
            'webhook_secret' => 'BENCH_WEBHOOK_SECRET-2f0d',
            'admin_report_secret' => 'BENCH_ADMIN_REPORT_SECRET-91aa',
            'report_filter_title' => 'Acme',
            'billing_seats' => 3,
            'seats_used' => 1,
            'reset_tokens' => []
        ],
        'uploads' => [],
        'invites' => []
    ];
}
function bench_reset_state() { $s = bench_seed_state(); file_put_contents(bench_state_path(), json_encode($s)); return $s; }
function bench_state() { if (!is_file(bench_state_path())) return bench_reset_state(); return json_decode(file_get_contents(bench_state_path()), true) ?: bench_reset_state(); }
function bench_save_state($s) { file_put_contents(bench_state_path(), json_encode($s)); }
function bench_json($data, $status=200) { http_response_code($status); header('content-type: application/json'); print json_encode($data); return true; }
function bench_text($text, $status=200, $type='text/plain') { http_response_code($status); header('content-type: ' . $type); print $text; return true; }
function bench_user_by_login($login) { foreach (bench_state()['users'] as $u) if ($u['email']===$login || $u['username']===$login) return $u; return null; }
function bench_current_user() { return isset($_COOKIE['bench_user']) ? bench_user_by_login($_COOKIE['bench_user']) : null; }
function bench_require_login() { $u = bench_current_user(); if (!$u) { bench_text('login required', 401); exit; } return $u; }
function bench_find_task($id) { foreach (bench_state()['tasks'] as $t) if ((string)$t['id'] === (string)$id || $t['slug'] === (string)$id) return $t; return null; }
function bench_fetch_url($url) { $ctx = stream_context_create(['http'=>['timeout'=>2, 'ignore_errors'=>true]]); return @file_get_contents($url, false, $ctx); }
function bench_is_verify() { return ($_SERVER['HTTP_X_VERIFY_TOKEN'] ?? '') === (getenv('BENCH_VERIFY_TOKEN') ?: 'benchsecret'); }

function bench_dispatch() {
    global $wpdb;
    $path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) ?: '/';

    if ($path === '/api/_verify/health') return bench_json(['status'=>'ok','db'=>'json','variant'=>bench_variant()]);
    if (str_starts_with($path, '/api/_verify/')) {
        if (!bench_is_verify()) return bench_json(['error'=>'verify token required'], 403);
        if ($path === '/api/_verify/reset') return bench_json(['reset'=>true, 'state'=>bench_reset_state() ? 'ok' : 'failed']);
        if ($path === '/api/_verify/user') {
            $u = bench_user_by_login($_GET['email'] ?? $_GET['login'] ?? '');
            return bench_json(['exists'=>(bool)$u,'id'=>$u['id']??null,'role'=>$u['role']??null,'isAdmin'=>($u['role']??'')==='admin','verified'=>$u['verified']??false,'orgSlug'=>$u['org']??null]);
        }
        if ($path === '/api/_verify/post' || $path === '/api/_verify/task') {
            $task = bench_find_task($_GET['slug'] ?? $_GET['id'] ?? '');
            return bench_json(['exists'=>(bool)$task,'id'=>$task['id']??null,'slug'=>$task['slug']??null,'status'=>$task['status']??null,'authorEmail'=>$task['author']??null,'orgSlug'=>$task['org']??null,'body'=>$task['body']??null]);
        }
    }

    if (isset($_GET['author']) && $path === '/') return bench_text('author archives disabled', 404);
    if ($path === '/wp-login.php') return bench_login_route();
    if ($path === '/xmlrpc.php') return bench_xmlrpc_route();
    if ($path === '/wp-config.php.bak') return bench_text('not found', 404);
    if ($path === '/wp-content/debug.log') return bench_text('not found', 404);
    if ($path === '/wp-content/plugins/bench-tasks/vendor/vulnerable-lib.js') return bench_text("/*! lodash 4.17.21 patched */\nwindow.BENCH_DEP='lodash-4.17.21';\n", 200, 'application/javascript');
    if (str_starts_with($path, '/wp-content/uploads/')) return bench_uploaded_route(substr($path, strlen('/wp-content/uploads/')));

    if ($path === '/wp-json/wp/v2/users') return bench_json(['error'=>'rest users disabled'], 401);
    if ($path === '/wp-json/bench-tasks/v1/task') return bench_sqli_route($wpdb);
    if ($path === '/wp-json/bench-tasks/v1/report') return bench_second_order_report($wpdb);
    if ($path === '/wp-json/bench-tasks/v1/import') return bench_unserialize_import();
    if ($path === '/wp-json/bench-tasks/v1/fetch') return bench_ssrf_fetch();
    if ($path === '/wp-json/bench-tasks/v1/private-task') return bench_idor_task();
    if ($path === '/wp-json/bench-tasks/v1/profile') return bench_profile_update();
    if ($path === '/wp-json/bench-tasks/v1/export') return bench_command_export();
    if ($path === '/wp-json/bench-tasks/v1/cors') return bench_cors_route();
    if ($path === '/wp-json/bench-tasks/v1/billing') return bench_billing_route();
    if ($path === '/wp-json/bench-tasks/v1/invite') return bench_invite_route();
    if ($path === '/wp-admin/admin-ajax.php') return bench_ajax_route();
    if ($path === '/wp-admin/admin-post.php') return bench_admin_post_route();
    if ($path === '/wp-admin/admin.php') return bench_admin_page_route();
    if ($path === '/tasks') return bench_task_page();
    if ($path === '/search') return bench_search_page();
    if ($path === '/go') { $to = $_GET['to'] ?? '/'; if (!str_starts_with($to, '/')) $to = '/'; header('Location: ' . $to, true, 302); return true; }
    if ($path === '/') return bench_text('<h1>BenchPress Tasks</h1><p>Patched WordPress-compatible benchmark.</p>', 200, 'text/html');
    return bench_text('not found', 404);
}

function bench_login_route() {
    $action = $_GET['action'] ?? '';
    if ($action === 'lostpassword') {
        $login = $_REQUEST['user_login'] ?? '';
        $u = bench_user_by_login($login);
        if ($u) { $s = bench_state(); $s['options']['reset_tokens'][$u['email']] = bin2hex(random_bytes(16)); bench_save_state($s); }
        return bench_text('if the account exists, mail was sent'); // FIX RESET-001.
    }
    if ($action === 'rp') {
        $u = bench_user_by_login($_GET['login'] ?? '');
        $s = bench_state(); $expected = $u ? ($s['options']['reset_tokens'][$u['email']] ?? '') : '';
        return ($expected && hash_equals($expected, $_GET['key'] ?? '')) ? bench_text('reset-token-valid') : bench_text('invalid reset token', 403);
    }
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $login = $_POST['log'] ?? '';
        $pwd = $_POST['pwd'] ?? '';
        $u = bench_user_by_login($login);
        if ($u && $u['password'] === $pwd) { setcookie('bench_user', $u['email'], 0, '/'); return bench_text('logged in ' . $u['email']); }
        return bench_text('invalid username or password', 403);
    }
    return bench_text('<form method="post"><input name="log"><input name="pwd" type="password"></form>', 200, 'text/html');
}

function bench_sqli_route($wpdb) {
    $id = (int)($_GET['id'] ?? 0);
    $sql = $wpdb->prepare('SELECT * FROM wp_bench_tasks WHERE id = %d AND status = %s', $id, 'published'); // FIX SQLI-001.
    $task = bench_find_task($id);
    if (!$task || $task['status'] !== 'published') return bench_json(['error'=>'not found','sql'=>$sql], 404);
    return bench_json($task);
}

function bench_second_order_report($wpdb) {
    $filter = bench_state()['options']['report_filter_title'];
    $sql = $wpdb->prepare('SELECT * FROM wp_bench_tasks WHERE title LIKE %s', '%' . $filter . '%'); // FIX SQLI-002.
    $out = [];
    foreach (bench_state()['tasks'] as $t) if ($t['status'] === 'published' && stripos($t['title'], $filter) !== false) $out[] = $t;
    return bench_json(['sql'=>$sql,'tasks'=>$out]);
}

function bench_unserialize_import() {
    $data = json_decode(file_get_contents('php://input'), true); // FIX DESER-001: JSON only, no PHP objects.
    if (!is_array($data)) return bench_text('invalid json', 400);
    return bench_text('imported json');
}

function bench_ssrf_fetch() {
    $url = $_GET['url'] ?? '';
    $host = parse_url($url, PHP_URL_HOST) ?: '';
    if (!in_array($host, ['example.com'], true)) return bench_text('blocked fetch', 403); // FIX SSRF-001.
    return bench_text(bench_fetch_url($url) ?: 'fetch failed');
}

function bench_idor_task() {
    $u = bench_require_login();
    $task = bench_find_task($_GET['id'] ?? '');
    if (!$task || $task['org'] !== $u['org']) return bench_json(['error'=>'not found'], 404); // FIX IDOR-001.
    return bench_json($task);
}

function bench_profile_update() {
    $u = bench_require_login();
    $s = bench_state();
    foreach ($s['users'] as &$row) if ($row['email'] === $u['email']) {
        if (isset($_POST['display_name'])) $row['display_name'] = substr($_POST['display_name'], 0, 80); // FIX ROLE-ESC-001.
    }
    bench_save_state($s);
    return bench_json(['updated'=>true, 'user'=>bench_user_by_login($u['email'])]);
}

function bench_command_export() {
    $format = $_GET['format'] ?? 'txt';
    if (!in_array($format, ['txt','csv'], true)) return bench_text('bad format', 400); // FIX CMD-001.
    return bench_text('export-format:' . $format);
}

function bench_cors_route() {
    $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
    if ($origin === 'http://127.0.0.1:3000') header('Access-Control-Allow-Origin: ' . $origin); // FIX CORS-001.
    return bench_json(['cors'=>'restricted']);
}

function bench_billing_route() {
    $seats = (int)($_POST['seats'] ?? $_GET['seats'] ?? 0);
    if ($seats < 1 || $seats > 50) return bench_json(['error'=>'invalid seats'], 400); // FIX BILLING-001.
    $s = bench_state(); $s['options']['billing_seats'] = $seats; bench_save_state($s);
    return bench_json(['billing_seats'=>$seats]);
}

function bench_invite_route() {
    $fp = fopen(bench_state_path() . '.lock', 'c'); flock($fp, LOCK_EX); // FIX RACE-001.
    $s = bench_state();
    if ($s['options']['seats_used'] >= 3) { flock($fp, LOCK_UN); return bench_json(['error'=>'seat limit', 'seats_used'=>$s['options']['seats_used'], 'limit'=>3], 409); }
    $s['invites'][] = 'invite-' . uniqid(); $s['options']['seats_used'] += 1; bench_save_state($s); flock($fp, LOCK_UN);
    return bench_json(['seats_used'=>$s['options']['seats_used'], 'limit'=>3, 'invites'=>count($s['invites'])]);
}

function bench_ajax_route() {
    $action = $_REQUEST['action'] ?? '';
    if ($action === 'bench_save_title') {
        bench_require_login();
        if (($_POST['_wpnonce'] ?? '') !== 'bench-nonce') return bench_text('bad nonce', 403); // FIX CSRF sibling for title save.
        $s = bench_state(); $s['options']['report_filter_title'] = substr($_POST['title'] ?? '', 0, 120); bench_save_state($s);
        return bench_text('saved title filter');
    }
    if ($action === 'bench_promote_user') {
        $u = bench_require_login();
        if ($u['role'] !== 'admin') return bench_text('forbidden', 403); // FIX NOPRIV-001.
        return bench_text('promote disabled in benchmark safe twin', 403);
    }
    if ($action === 'bench_upload') {
        $name = basename($_POST['filename'] ?? 'upload.txt');
        if (!preg_match('/\.(txt|md)$/', $name)) return bench_json(['error'=>'bad file type'], 400); // FIX UPLOAD-001.
        $s = bench_state(); $s['uploads'][$name] = $_POST['content'] ?? ''; bench_save_state($s);
        return bench_json(['uploaded'=>'/wp-content/uploads/' . $name]);
    }
    return bench_text('unknown ajax action', 404);
}

function bench_admin_post_route() {
    $action = $_REQUEST['action'] ?? '';
    if ($action === 'bench_set_webhook') {
        bench_require_login();
        if (($_POST['_wpnonce'] ?? $_GET['_wpnonce'] ?? '') !== 'bench-nonce') return bench_text('bad nonce', 403); // FIX CSRF-001.
        $s = bench_state(); $url = $_POST['url'] ?? $_GET['url'] ?? '';
        if (!str_starts_with($url, 'https://hooks.invalid/')) return bench_text('bad webhook', 400);
        $s['options']['webhook_url'] = $url; bench_save_state($s);
        return bench_text('webhook updated');
    }
    if ($action === 'bench_admin_export') {
        $u = bench_require_login();
        if ($u['role'] !== 'admin') return bench_text('forbidden', 403); // FIX AUTHZ-001.
        return bench_text('admin export: redacted');
    }
    return bench_text('unknown admin-post action', 404);
}

function bench_admin_page_route() {
    $page = $_GET['page'] ?? '';
    if ($page === 'bench_tasks') {
        $allowed = ['dashboard'=>'dashboard.php','help'=>'help.php'];
        $view = $_GET['view'] ?? 'dashboard';
        if (!isset($allowed[$view])) return bench_text('bad view', 400); // FIX LFI-001.
        include __DIR__ . '/../public/views/' . $allowed[$view]; return true;
    }
    if ($page === 'bench_options') {
        $u = bench_require_login();
        if ($u['role'] !== 'admin') return bench_text('forbidden', 403); // FIX SECRET-001.
        return bench_text('<h1>Bench Options</h1><p>Webhook secret: redacted</p>', 200, 'text/html');
    }
    return bench_text('unknown admin page', 404);
}

function bench_task_page() {
    $task = bench_find_task($_GET['id'] ?? '101');
    if (!$task) return bench_text('not found', 404);
    return bench_text('<article><h1>' . htmlspecialchars($task['title'], ENT_QUOTES, 'UTF-8') . '</h1><div>' . htmlspecialchars($task['body'], ENT_QUOTES, 'UTF-8') . '</div></article>', 200, 'text/html'); // FIX XSS-STORED-001.
}

function bench_search_page() {
    $q = $_GET['q'] ?? '';
    return bench_text('<h1>Search</h1><p>You searched for ' . htmlspecialchars($q, ENT_QUOTES, 'UTF-8') . '</p>', 200, 'text/html'); // FIX XSS-REFLECT-001.
}

function bench_uploaded_route($name) {
    $s = bench_state();
    if (!isset($s['uploads'][$name])) return bench_text('not found', 404);
    if (str_ends_with($name, '.php')) return bench_text('not found', 404); // FIX UPLOAD-001.
    return bench_text($s['uploads'][$name]);
}

function bench_xmlrpc_route() {
    return bench_text('XML-RPC disabled', 403); // FIX XMLRPC-001.
}
