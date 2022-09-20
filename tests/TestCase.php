<?php

namespace j3j5\HmacBcryptLaravel\Tests;

use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use j3j5\HmacBcryptLaravel\HmacBcryptHasher;
use RuntimeException;

class TestCase extends \Orchestra\Testbench\TestCase
{
    /**
     * Get package providers.
     *
     * @param  \Illuminate\Foundation\Application  $app
     *
     * @return array<int, string>
     */
    protected function getPackageProviders($app)
    {
        return [
            'j3j5\HmacBcryptLaravel\HashServiceProvider',
        ];
    }

    /**
     * Setup the test environment.
     */
    public function setUp(): void
    {
        parent::setUp();

        $this->app['config']->set('hashing.driver', 'hmac-bcrypt');
    }

    public function test_service_container_returns_correct_hash_driver()
    {
        $this->assertInstanceOf(HmacBcryptHasher::class, $this->app['hash']->driver());
    }

    public function test_hash_make_returns_hash()
    {
        $pass = Str::random();
        $hash = Hash::make($pass);

        $this->assertNotEquals($pass, $hash);
    }

    public function test_hash_make_output_matches_hash_verify()
    {
        $pass = Str::random();
        $hash = Hash::make($pass);

        $this->assertTrue(Hash::check($pass, $hash));
    }

    public function test_hash_check_works_as_expected_with_pregenerated_hash()
    {
        $pass = 'test-pass';
        $expected = '$2a$13$v.vnO5oVlX/5zJM9TTXSz.JMdh9WwErhl6x9XMOEBs5x1R1FxuPC29TMJSMeAEnUlkEgbZw6r0FFZ9jFN07eykXAMgNZH3WrZSqxQkj4qKEQ';
        $this->assertTrue(Hash::check($pass, $expected));
    }

    public function test_hash_needs_rehash_returns_false_if_no_changes()
    {
        $pass = Str::random();
        $hash = Hash::make($pass);

        $this->assertFalse(Hash::needsRehash($hash));
    }

    public function test_hash_needs_rehash_returns_true_for_extra_cost()
    {
        $pass = Str::random();
        $hash = Hash::make($pass);

        $this->assertTrue(Hash::needsRehash($hash, ['rounds' => config('hashing.hmac-bcrypt.rounds') + 1]));
    }

    public function test_hash_needs_rehash_returns_true_for_different_algo()
    {
        $pass = Str::random();
        $hash = app('hash')->driver('bcrypt')->make($pass);

        $this->assertTrue(Hash::needsRehash($hash));
    }

    public function test_hash_with_wrong_custom_salt_throws_exception()
    {
        $pass = Str::random();

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Salt should be ' . HmacBcryptHasher::BCRYPT_SALT_CHARS . ' chars long');

        $hash = Hash::make($pass, ['salt' => 'sweetsalt']);
    }
}
