<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

// The "Advanced" tools panel backend. The panel is a fragment the dashboard
// fetches only after the Advanced button is clicked, and this endpoint is
// referenced nowhere else - not in the served HTML, not in the nav manifest - so
// it is only discoverable by running the page and interacting with it.
class AdvancedController extends Controller
{
    // XXE-001 (CWE-611): the "import mapping" feature parses caller-supplied XML
    // with entity substitution and external DTD loading enabled, so a document
    // with a SYSTEM entity reads local files (or reaches internal URLs) and the
    // expanded value comes back in the response. The safe twin parses with
    // LIBXML_NONET and no entity substitution.
    public function importMapping(Request $request)
    {
        $xml = (string) $request->getContent();
        if ($xml === '') {
            return response()->json(['error' => 'xml body required'], 400);
        }

        libxml_use_internal_errors(true);
        $doc = new \DOMDocument();
        $doc->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD);

        $out = [];
        foreach ($doc->getElementsByTagName('field') as $field) {
            $out[] = $field->textContent;
        }

        return response()->json(['mapping' => $out, 'root' => $doc->documentElement?->textContent]);
    }
}
