<?php

namespace Marcvanh\LaravelBotBlock;

use Illuminate\Support\ServiceProvider;
use Illuminate\Contracts\Http\Kernel;

class LaravelBotBlockServiceProvider extends ServiceProvider
{
    public function register()
    {
        $this->mergeConfigFrom(__DIR__.'/config/laravel-bot-block.php', 'laravel-bot-block');
    }

    public function boot(Kernel $kernel)
    {
        // Add the middleware to the global middleware stack
        $kernel->pushMiddleware(\Marcvanh\LaravelBotBlock\Middleware\BotBlockMiddleware::class);

        // Publish the config file
        $this->publishes([
            __DIR__.'/config/laravel-bot-block.php' => $this->app->configPath('laravel-bot-block.php'),
        ], 'config');
    }
}