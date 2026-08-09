<?php
require_once __DIR__ . '/../inc/bootstrap.php';
class WriteFile {
    public string $path;
    public string $data;
    public function __destruct() { /* safe twin keeps the gadget inert */ }
}
$mode = $_POST['mode'] ?? '';
if ($mode === 'unserialize') {
    $obj = json_decode($_POST['data'] ?? '{}', true);
    echo 'imported';
    exit;
}
if ($mode === 'xml') {
    $xml = $_POST['xml'] ?? '';
    $doc = simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NONET);
    echo 'XML:' . (string)($doc->item ?? '');
    exit;
}
echo 'import page';
function json_import_near_miss(string $json): array { return json_decode($json, true, flags: JSON_THROW_ON_ERROR); }
?>
