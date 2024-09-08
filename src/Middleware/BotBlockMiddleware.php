<?php

namespace Marcvanh\LaravelBotBlock\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Str;

class BotBlockMiddleware
{
    public function handle (Request $request, Closure $next)
    {
        // skip if disabled
        if (!config('laravel-bot-block.enable')) {
            return $next($request);
        }
        
        // get client IP with cloudflare (or other proxy) support
        $clientIp = $_SERVER["HTTP_CF_CONNECTING_IP"] ?? $_SERVER["HTTP_X_FORWARDED_FOR"] ?? $_SERVER['REMOTE_ADDR'];
        
        // skip local & invalid IP addresses
        if (!$this->isValidPublicIp($clientIp)) {
            return $next($request);
        }
        
        // skip if logged in
        if (config('laravel-bot-block.whitelist_users_logged_in', false)) {
            if ($this->isLoggedInToAnyGuard()) {
                return $next($request);
            }
        }
        
        // skip if whitelist match
        if ($this->isMatch($request->decodedPath(), config('laravel-bot-block.whitelist.uri', []))) {
            return $next($request);
        }
        if ($this->isMatch($clientIp, config('laravel-bot-block.whitelist.ip', []))) {
            return $next($request);
        }
        
        // check if this IP is currently blocked. if so, deny access to site
        if (RateLimiter::tooManyAttempts(config('laravel-bot-block.cache_key').":{$clientIp}", 1)) {
            abort(config('laravel-bot-block.response_code', 444));
        }
        
        //////////////////
        // BOT CHECKS
        //////////////////
        
        // require specific domain in URL? (prevents direct IP access)
        if (config('laravel-bot-block.require_domain') && app()->isProduction()) {
            $checkHost = strtolower($request->getHost());
            $domain = strtolower(config('laravel-bot-block.require_domain'));
            if ($checkHost !== $domain && !str_ends_with($checkHost, ".{$domain}")) {
                $this->blockIp($clientIp);
                abort(config('laravel-bot-block.response_code', 444));
            }
        }
        
        // test for probing for vulnerable paths in URL...
        if ($this->isMatch($request->decodedPath(), config('laravel-bot-block.block.uri', []))) {
            $this->blockIp($clientIp);
            abort(config('laravel-bot-block.response_code', 444));
        }
        if ($this->isMatch($clientIp, config('laravel-bot-block.block.ip', []))) {
            $this->blockIp($clientIp);
            abort(config('laravel-bot-block.response_code', 444));
        }
        
        return $next($request);
    }
    
    /**
     * case-insensitive
     */
    private function isMatch (string $string, array $rules): bool
    {
        $string = strtolower($string);
        
        if (!empty($rules['exact']) && in_array($string, array_map('strtolower', $rules['exact']))) {
            return true;
        }
        
        if (!empty($rules['startswith']) && Str::startsWith($string, array_map('strtolower', $rules['startswith']))) {
            return true;
        }
        
        if (!empty($rules['contains']) && Str::contains($string, $rules['contains'], true)) {
            return true;
        }
        
        if (!empty($rules['endswith']) && Str::endsWith($string, array_map('strtolower', $rules['endswith']))) {
            return true;
        }
        
        return false;
    }
    
    private function blockIp (string $ip = null): void
    {
        if (!empty($ip)) {
            $seconds = config('laravel-bot-block.block_seconds');
            
            // block the ip
            RateLimiter::hit(config('laravel-bot-block.cache_key').":{$ip}", $seconds);
            
            // log this
            if (config('laravel-bot-block.logging_enabled', true)) {
                try {
                    logger()->info("Blocked IP {$ip} for {$seconds} seconds", [
                        'request' => request()->all(),
                        'url' => request()->fullUrl(),
                        'user_ip_address' => $ip,
                        'user_country' => $_SERVER['HTTP_CF_IPCOUNTRY'] ?? null,
                    ]);
                } catch (\Throwable) {
                }
            }
        }
    }
    
    private function isValidPublicIp ($ip): bool
    {
        // Check if the IP is valid and not in private or reserved ranges
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)
            !== false;
    }

    private function isLoggedInToAnyGuard(): bool
    {
        try {
            foreach (array_keys(config('auth.guards', [])) as $guard) {
                if (auth()->guard($guard)->check()) {
                    return true;
                }
            }
        } catch (\Throwable) {
        }

        return false;
    }

}