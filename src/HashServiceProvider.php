<?php

namespace j3j5\HmacBcryptLaravel;

use Illuminate\Contracts\Support\DeferrableProvider;
use Illuminate\Support\ServiceProvider;
use RuntimeException;

class HashServiceProvider extends ServiceProvider implements DeferrableProvider
{
    /**
     * Register the service provider.
     *
     * @return void
     */
    public function register()
    {
        $this->app->singleton('hash', function ($app) {
            return new HashManager($app);
        });

        $this->app->singleton('hash.driver', function ($app) {
            return $app['hash']->driver();
        });

        $configPath = realpath(__DIR__ . '/../config/hashing.php');
        if ($configPath === false) {
            throw new RuntimeException('Hashing config file could not be found on hmac-bcrypt package');
        }
        $this->mergeConfigFrom($configPath, 'hashing');
    }

    /**
     * Get the services provided by the provider.
     *
     * @return array<int, string>
     */
    public function provides()
    {
        return ['hash', 'hash.driver'];
    }
}
