<?php
// BenchPress Tasks: WordPress-compatible intentionally vulnerable plugin app.
// Vulnerabilities in this file are deliberate benchmark fixtures.

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

function bench_variant() { return getenv('VARIANT') ?: 'vuln'; }
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

    if (isset($_GET['author']) && $path === '/') {
        $id = (int)$_GET['author'];
        $names = [1=>'admin',2=>'editor',3=>'user1',4=>'user2'];
        if (isset($names[$id])) { header('Location: /author/' . $names[$id], true, 302); return true; }
    }

    if ($path === '/wp-login.php') return bench_login_route();
    if ($path === '/xmlrpc.php') return bench_xmlrpc_route();
    if ($path === '/wp-config.php.bak') return bench_text("AUTH_KEY='weak-salt';\nSECURE_AUTH_KEY='weak-salt';\nDB_PASSWORD='wordpress-local-password';\n", 200);
    if ($path === '/wp-content/debug.log') return bench_text("[debug] WP_DEBUG_DISPLAY enabled\nFatal error: stack trace leaks /app/public/wp-config.php\n", 200);
    if ($path === '/wp-content/plugins/bench-tasks/vendor/vulnerable-lib.js') return bench_text("/*! lodash 4.17.11 vulnerable CVE-2019-10744 */\nwindow.BENCH_VULN_DEP='lodash-4.17.11';\n", 200, 'application/javascript');
    if (str_starts_with($path, '/wp-content/uploads/')) return bench_uploaded_route(substr($path, strlen('/wp-content/uploads/')));

    if ($path === '/wp-json/wp/v2/users') return bench_json(array_map(fn($u)=>['id'=>$u['id'],'slug'=>$u['username'],'name'=>$u['username']], bench_state()['users']));
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
    if ($path === '/go') { header('Location: ' . ($_GET['to'] ?? '/'), true, 302); return true; }
    if ($path === '/') return bench_text('<h1>BenchPress Tasks</h1><p>Intentionally vulnerable WordPress-compatible benchmark.</p>', 200, 'text/html');
    return bench_text('not found', 404);
}

function bench_login_route() {
    $action = $_GET['action'] ?? '';
    if ($action === 'lostpassword') {
        $login = $_REQUEST['user_login'] ?? '';
        $u = bench_user_by_login($login);
        $token = $u ? md5($u['email'] . ':' . date('Y-m-d')) : md5($login . ':' . date('Y-m-d'));
        return bench_text('reset token: ' . $token);
    }
    if ($action === 'rp') {
        $u = bench_user_by_login($_GET['login'] ?? '');
        $expected = $u ? md5($u['email'] . ':' . date('Y-m-d')) : '';
        return ($expected && hash_equals($expected, $_GET['key'] ?? '')) ? bench_text('reset-token-valid') : bench_text('invalid reset token', 403);
    }
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $login = $_POST['log'] ?? '';
        $pwd = $_POST['pwd'] ?? '';
        if ($login === 'admin' && $pwd === 'admin') { setcookie('bench_user', 'service@bench.local', 0, '/'); return bench_text('logged in default admin credential as service'); }
        $u = bench_user_by_login($login);
        if ($u && $u['password'] === $pwd) { setcookie('bench_user', $u['email'], 0, '/'); return bench_text('logged in ' . $u['email']); }
        return bench_text('invalid username or password', 403);
    }
    return bench_text('<form method="post"><input name="log"><input name="pwd" type="password"></form>', 200, 'text/html');
}

function bench_sqli_route($wpdb) {
    $id = $_GET['id'] ?? '0';
    $sql = "SELECT * FROM wp_bench_tasks WHERE id = $id"; // VULN SQLI-001: wpdb query without prepare.
    $wpdb->query($sql);
    $tasks = bench_state()['tasks'];
    if (preg_match('/\bor\b\s*1\s*=\s*1/i', $id)) return bench_json(['sql'=>$sql,'tasks'=>$tasks]);
    $task = bench_find_task($id);
    return $task ? bench_json($task) : bench_json(['error'=>'not found','sql'=>$sql], 404);
}

function bench_second_order_report($wpdb) {
    $filter = bench_state()['options']['report_filter_title'];
    $sql = "SELECT * FROM wp_bench_tasks WHERE title LIKE '%$filter%'"; // VULN SQLI-002: stored option flows into SQL.
    $wpdb->query($sql);
    $out = [];
    foreach (bench_state()['tasks'] as $t) if (stripos($t['title'], trim($filter, "%'") ) !== false || preg_match('/\bor\b\s*1\s*=\s*1/i', $filter)) $out[] = $t;
    return bench_json(['sql'=>$sql,'tasks'=>$out]);
}

function bench_unserialize_import() {
    $blob = file_get_contents('php://input');
    @unserialize($blob); // VULN DESER-001: user-controlled PHP object deserialization.
    return bench_text($GLOBALS['bench_unserialize_result'] ?? 'imported');
}

function bench_ssrf_fetch() {
    $url = $_GET['url'] ?? '';
    $body = bench_fetch_url($url); // VULN SSRF-001: arbitrary server-side fetch.
    return bench_text($body === false ? 'fetch failed' : $body);
}

function bench_idor_task() {
    bench_require_login();
    $task = bench_find_task($_GET['id'] ?? ''); // VULN IDOR-001: no org/author scoping.
    return $task ? bench_json($task) : bench_json(['error'=>'not found'], 404);
}

function bench_profile_update() {
    $u = bench_require_login();
    $s = bench_state();
    foreach ($s['users'] as &$row) if ($row['email'] === $u['email']) {
        foreach ($_POST as $k=>$v) $row[$k] = $v; // VULN ROLE-ESC-001: role over-posting.
    }
    bench_save_state($s);
    return bench_json(['updated'=>true, 'user'=>bench_user_by_login($u['email'])]);
}

function bench_command_export() {
    $format = $_GET['format'] ?? 'txt';
    $cmd = "printf 'export-format:'" . $format; // VULN CMD-001: shell command includes user input.
    return bench_text(shell_exec($cmd) ?: '');
}

function bench_cors_route() {
    $origin = $_SERVER['HTTP_ORIGIN'] ?? '*';
    header('Access-Control-Allow-Origin: ' . $origin); // VULN CORS-001: reflect arbitrary origin with credentials.
    header('Access-Control-Allow-Credentials: true');
    return bench_json(['cors'=>'reflected']);
}

function bench_billing_route() {
    $s = bench_state();
    $s['options']['billing_seats'] = (int)($_POST['seats'] ?? $_GET['seats'] ?? 0); // VULN BILLING-001: negative/huge value accepted.
    bench_save_state($s);
    return bench_json(['billing_seats'=>$s['options']['billing_seats']]);
}

function bench_invite_route() {
    $s = bench_state();
    $slots = (int)($_POST['slots'] ?? $_GET['slots'] ?? 1);
    $used = $s['options']['seats_used'];
    if ($used < 3) { // VULN RACE-001: read/check/write without lock and trusts requested slots.
        usleep(150000);
        for ($i=0; $i<$slots; $i++) $s['invites'][] = 'invite-' . uniqid();
        $s['options']['seats_used'] = $used + $slots;
        bench_save_state($s);
    }
    return bench_json(['seats_used'=>$s['options']['seats_used'], 'limit'=>3, 'invites'=>count($s['invites'])]);
}

function bench_ajax_route() {
    $action = $_REQUEST['action'] ?? '';
    if ($action === 'bench_save_title') {
        $u = bench_require_login();
        $s = bench_state();
        $s['options']['report_filter_title'] = $_POST['title'] ?? ''; // VULN SQLI-002 source: stored unchecked for later query.
        bench_save_state($s);
        return bench_text('saved title filter');
    }
    if ($action === 'bench_promote_user') {
        $email = $_REQUEST['email'] ?? 'user1@bench.local'; // VULN NOPRIV-001: privileged wp_ajax_nopriv-style action.
        $s = bench_state();
        foreach ($s['users'] as &$u) if ($u['email'] === $email) $u['role'] = 'admin';
        bench_save_state($s);
        return bench_text('promoted ' . $email);
    }
    if ($action === 'bench_upload') {
        $name = basename($_POST['filename'] ?? 'upload.txt');
        $content = $_POST['content'] ?? '';
        $s = bench_state();
        $s['uploads'][$name] = $content; // VULN UPLOAD-001: no extension/MIME validation; PHP webshell allowed.
        bench_save_state($s);
        return bench_json(['uploaded'=>'/wp-content/uploads/' . $name]);
    }
    return bench_text('unknown ajax action', 404);
}

function bench_admin_post_route() {
    $action = $_REQUEST['action'] ?? '';
    if ($action === 'bench_set_webhook') {
        bench_require_login();
        $s = bench_state();
        $s['options']['webhook_url'] = $_POST['url'] ?? $_GET['url'] ?? ''; // VULN CSRF-001: missing nonce on state change.
        bench_save_state($s);
        return bench_text('webhook updated without nonce');
    }
    if ($action === 'bench_admin_export') {
        bench_require_login(); // VULN AUTHZ-001: missing current_user_can('manage_options').
        return bench_text('admin export: ' . bench_state()['options']['admin_report_secret']);
    }
    return bench_text('unknown admin-post action', 404);
}

function bench_admin_page_route() {
    $page = $_GET['page'] ?? '';
    if ($page === 'bench_tasks') {
        $view = $_GET['view'] ?? 'dashboard.php';
        $target = __DIR__ . '/../public/views/' . $view; // VULN LFI-001: user controls include target.
        if (str_contains($view, 'wp-config.php.bak')) return bench_text(file_get_contents(__DIR__ . '/../public/wp-config.php.bak'));
        if (is_file($target)) { include $target; return true; }
        return bench_text('missing view', 404);
    }
    if ($page === 'bench_options') {
        bench_require_login();
        $s = bench_state();
        return bench_text('<h1>Bench Options</h1><p>Webhook secret: ' . $s['options']['webhook_secret'] . '</p>', 200, 'text/html'); // VULN SECRET-001: option secret echoed.
    }
    return bench_text('unknown admin page', 404);
}

function bench_task_page() {
    $task = bench_find_task($_GET['id'] ?? '101');
    if (!$task) return bench_text('not found', 404);
    return bench_text('<article><h1>' . $task['title'] . '</h1><div>' . $task['body'] . '</div></article>', 200, 'text/html'); // VULN XSS-STORED-001: stored body unescaped.
}

function bench_search_page() {
    $q = $_GET['q'] ?? '';
    return bench_text('<h1>Search</h1><p>You searched for ' . $q . '</p>', 200, 'text/html'); // VULN XSS-REFLECT-001: reflected q unescaped.
}

function bench_uploaded_route($name) {
    $s = bench_state();
    if (!isset($s['uploads'][$name])) return bench_text('not found', 404);
    if (str_ends_with($name, '.php')) return bench_text('WEB-SHELL uid=33(www-data) cmd=' . ($_GET['cmd'] ?? '')); // VULN UPLOAD-001 sink.
    return bench_text($s['uploads'][$name]);
}

function bench_xmlrpc_route() {
    $body = file_get_contents('php://input');
    if (str_contains($body, 'pingback.ping')) {
        preg_match_all('/<string>([^<]+)<\/string>/', $body, $m);
        $target = $m[1][1] ?? $m[1][0] ?? '';
        $fetched = $target ? bench_fetch_url($target) : '';
        return bench_text('<methodResponse><params><param><value><string>pingback fetched ' . htmlspecialchars((string)$fetched) . '</string></value></param></params></methodResponse>', 200, 'text/xml');
    }
    return bench_text('<methodResponse><params><param><value><string>xmlrpc enabled</string></value></param></params></methodResponse>', 200, 'text/xml');
}
