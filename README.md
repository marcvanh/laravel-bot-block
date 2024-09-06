# Laravel Bot Block

A Laravel package to add custom security middleware. It monitors incoming requests, looking for bot activity. 
Any bot activity is blocked for a specified amount of time - 10 minutes by default. The end result is a pretty
good defense against probing scripts and bots.

Supports Cloudflare & other Proxies

### Installation

1. Install the package via Composer:

    ```bash
    composer require marcvanh/laravel-bot-block
    ```

2. (Optional) Publish the configuration file (for customization):

    ```bash
    php artisan vendor:publish --tag=config
    ```
