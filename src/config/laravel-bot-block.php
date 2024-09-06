<?php

return [
    
    // enable or disable this package
    'enable' => env('APP_ENV') === 'production',
    
    // response code when user blocked
    'response_code' => 444,
    
    // for preventing access via direct IP (always ignored outside production)
    // ONLY the domain e.g. 'google.com' - no wildcards or leading dots
    'require_domain' => '',
    
    // any matches here will override any blocks
    'whitelist' => [
        'ip' => [
            'exact' => [],
            'endswith' => [],
            'contains' => [],
            'startswith' => [],
        ],
        'uri' => [
            'exact' => [],
            'endswith' => [],
            'contains' => [],
            'startswith' => ['horizon', 'wp-content/'],
        ],
    ],
    
    // any matches here will be considered a bot/probe and be blocked
    'block' => [
        'ip' => [
            'exact' => [],
            'endswith' => [],
            'contains' => [],
            'startswith' => [],
        ],
        'uri' => [
            'exact' => [],
            'endswith' => [
                ".php", ".asp", ".aspx", ".jsp", ".rb", ".py", ".pl",
                ".cgi", ".cfm", ".cfc", ".dll", ".exe", ".sh", ".bat", ".cmd", ".ps1", ".jar",
                ".war", ".class", ".lua", ".sql",
            ],
            'contains' => ['xmlrpc', 'wp-admin', 'wp-login', "../"],
            'startswith' => [],
        ],
    ],
    
    // other settings
    'block_seconds' => 10 * 60,
    'cache_key' => 'ls-blocked-ip',

];