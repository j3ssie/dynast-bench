<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

// The "Advanced" tools panel backend. The panel is a fragment the dashboard
// fetches only after the Advanced button is clicked, and this endpoint is
// referenced nowhere else - not in the served HTML, not in the nav manifest - so
// it is only discoverable by running the page and interacting with it.
class AdvancedController extends Controller
{
    // FIXED XXE-001: the XML is parsed with no entity substitution and no network
    // access (LIBXML_NONET), and any DOCTYPE is rejected outright, so a SYSTEM
    // entity is neither expanded nor able to reach a file or URL.
    public function importMapping(Request $request)
    {
        $xml = (string) $request->getContent();
        if ($xml === '') {
            return response()->json(['error' => 'xml body required'], 400);
        }
        if (stripos($xml, '<!DOCTYPE') !== false) {
            return response()->json(['error' => 'DTDs are not allowed'], 400);
        }

        libxml_use_internal_errors(true);
        $doc = new \DOMDocument();
        $doc->loadXML($xml, LIBXML_NONET);

        $out = [];
        foreach ($doc->getElementsByTagName('field') as $field) {
            $out[] = $field->textContent;
        }

        return response()->json(['mapping' => $out, 'root' => $doc->documentElement?->textContent]);
    }
}
