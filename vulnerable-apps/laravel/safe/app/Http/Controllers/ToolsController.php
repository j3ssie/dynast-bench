<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Blade;
use Illuminate\Support\Facades\Http;

class ToolsController extends Controller
{
    // SSRF-001 (CWE-918): the server fetches an arbitrary attacker-supplied URL
    // and returns the body, so it can be pointed at the internal-only sink (or
    // cloud metadata). The safe twin allowlists the host and blocks private IPs.
    public function fetch(Request $request)
    {
        $url = (string) $request->query('url', '');
        $host = parse_url($url, PHP_URL_HOST) ?: '';
        $allowedHosts = ['example.com', 'www.example.com'];
        $ips = $host !== '' ? (gethostbynamel($host) ?: []) : [];
        foreach ($ips as $ip) {
            // block loopback / private / link-local ranges
            if (! filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                abort(400, 'blocked host');
            }
        }
        if (! in_array($host, $allowedHosts, true)) {
            abort(400, 'host not allowed');
        }
        $body = Http::timeout(4)->get($url)->body();

        return response($body)->header('Content-Type', 'text/plain');
    }

    // TRAVERSAL-001 (CWE-22): the filename is concatenated onto a base directory
    // and read with no containment check, so `?file=../../../../etc/passwd`
    // escapes the exports folder. The safe twin basenames the input and confirms
    // the resolved path stays inside the exports directory.
    public function download(Request $request)
    {
        $file = basename((string) $request->query('file', 'report.txt'));
        $base = storage_path('app/exports/');
        $path = realpath($base.$file);
        if ($path === false || strncmp($path, realpath($base), strlen(realpath($base))) !== 0) {
            abort(404);
        }
        $data = @file_get_contents($path);

        return response($data)->header('Content-Type', 'text/plain');
    }

    // CMD-001 (CWE-78): the export format is interpolated into a shell command,
    // so `?format=txt;id` runs id. The safe twin uses escapeshellarg / a fixed
    // allowlist of formats.
    public function export(Request $request)
    {
        $format = (string) $request->query('format', 'txt');
        if (! in_array($format, ['txt', 'csv', 'json'], true)) {
            $format = 'txt';
        }
        $out = shell_exec('echo generating report in '.escapeshellarg($format).' format');

        return response($out)->header('Content-Type', 'text/plain');
    }

    // SSTI-001 (CWE-1336/CWE-94): user input is compiled and evaluated as a
    // Blade template, so `?tpl={{ 7*7 }}` renders 49 and `{{ system('id') }}`
    // runs commands. The safe twin renders a *static* template with the input as
    // escaped data (see the mode=greet branch, NM-SSTI-001).
    public function preview(Request $request)
    {
        // NM-SSTI-001: static template + bound data — safe, present in both.
        if ($request->query('mode') === 'greet') {
            $html = Blade::render('Hello, {{ $name }}!', ['name' => (string) $request->query('name', '')]);

            return response($html)->header('Content-Type', 'text/plain');
        }

        // Render a STATIC template with the input as escaped, bound data — never
        // compile attacker input as a template.
        $tpl = (string) $request->query('tpl', 'Preview');
        $html = Blade::render('{{ $tpl }}', ['tpl' => $tpl]);

        return response($html)->header('Content-Type', 'text/plain');
    }

    // REDIRECT-001 (CWE-601): `next` is redirected to verbatim. The safe twin
    // only honours the allowlist branch below and sends everything else to '/'.
    public function go(Request $request)
    {
        $next = (string) $request->query('next', '/');

        // NM-REDIRECT-001: an allowlisted internal redirect of the same param —
        // safe, present in both variants.
        $allowed = ['dashboard' => '/dashboard', 'posts' => '/posts', 'home' => '/'];
        if (isset($allowed[$next])) {
            return redirect($allowed[$next]);
        }

        // Anything not on the allowlist goes home — no open redirect.
        return redirect('/');
    }

    // DEBUG-001 (CWE-489/CWE-209): APP_DEBUG=true in production. This diagnostics
    // endpoint divides by a caller-controlled number; with debug on, the
    // uncaught DivisionByZeroError renders a full stack trace + framework paths.
    // The safe twin sets APP_DEBUG=false so only a generic 500 is returned.
    public function diagnostics(Request $request)
    {
        $n = (int) $request->query('n', 0);
        $ratio = 100 / $n;

        return response()->json(['ratio' => $ratio]);
    }

    // DESER-001 (CWE-502): attacker-controlled data is unserialize()d, so a
    // serialized App\Support\Backup object triggers a file-write destructor.
    // NM-DESER-001: the mode=json branch decodes JSON instead (safe, both
    // variants). The safe twin replaces unserialize() with json_decode().
    public function import(Request $request)
    {
        $data = (string) $request->input('data', '');

        if ($request->input('mode') === 'json') {
            $decoded = json_decode($data, true);

            return response()->json(['ok' => true, 'keys' => is_array($decoded) ? array_keys($decoded) : []]);
        }

        // Never unserialize() attacker input — decode as data only.
        $obj = json_decode($data, true);

        return response()->json(['ok' => true, 'type' => gettype($obj)]);
    }
}
