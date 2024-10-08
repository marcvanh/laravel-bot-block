# Laravel Bot Block

A custom middleware package for Laravel. It monitors incoming requests, watching 
for bots/crawlers scanning for vulnerabilities. Any bot activity and the crawler is blocked 
for a specified amount of time (10 minutes by default). The end result is a pretty good 
defense against probing scripts, crawlers and bots.

Supports Cloudflare & other Proxies

### Installation

1. Install the package via Composer:

    ```bash
    composer require marcvanh/laravel-bot-block
    ```

2. (Optional) Publish the configuration file (for customization):

    ```bash
    php artisan vendor:publish --provider="Marcvanh\LaravelBotBlock\LaravelBotBlockServiceProvider"
    ```
