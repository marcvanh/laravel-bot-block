<?php

return [
    
    // enable or disable this package
    'enable' => env('LARAVEL_BOT_BLOCK_ENABLE', env('APP_ENV') === 'production'),
    
    // response code when user blocked
    'response_code' => env('LARAVEL_BOT_BLOCK_RESPONSE_CODE', 403),
    
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
            'startswith' => ['horizon'],
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
            'contains' => ['xmlrpc', 'wp-admin', 'wp-login', 'wp-content', "../"],
            'startswith' => [],
        ],
    ],
    
    // other settings
    'block_seconds' => 10 * 60,
    'cache_key' => 'bb-blocked-ip',
    'logging_enabled' => true,
    'debug_mode' => env('LARAVEL_BOT_BLOCK_DEBUG_MODE', false),

];