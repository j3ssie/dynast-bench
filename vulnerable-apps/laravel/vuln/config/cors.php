<?php

// CORS-001 (CWE-942): an over-permissive CORS policy. `allowed_origins_patterns`
// matches ANY origin (so the request Origin is reflected back) while
// `supports_credentials` is true — the exact combination that lets any site read
// authenticated responses. The safe twin pins a single origin and turns
// credentials off.
return [
    'paths' => ['*'],

    'allowed_methods' => ['*'],

    'allowed_origins' => [],

    'allowed_origins_patterns' => ['#^https?://.*$#'],

    'allowed_headers' => ['*'],

    'exposed_headers' => [],

    'max_age' => 0,

    'supports_credentials' => true,
];
