<?php

// A tight CORS policy: a single pinned origin and NO credentials.
return [
    'paths' => ['*'],

    'allowed_methods' => ['GET', 'POST'],

    'allowed_origins' => ['http://127.0.0.1:13311'],

    'allowed_origins_patterns' => [],

    'allowed_headers' => ['*'],

    'exposed_headers' => [],

    'max_age' => 0,

    'supports_credentials' => false,
];
