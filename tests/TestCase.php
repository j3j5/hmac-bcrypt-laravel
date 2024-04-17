<?php

namespace j3j5\HmacBcryptLaravel\Tests;

use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use j3j5\HmacBcryptLaravel\HmacBcryptHasher;
use Orchestra\Testbench\TestCase as OrchestraTestCase;
use RuntimeException;

class TestCase extends OrchestraTestCase
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

    public function test_hash_check_works_as_expected_with_pregenerated_hash()
    {
        $pass = 'test-pass';
        $expected = '$2a$13$v.vnO5oVlX/5zJM9TTXSz.JMdh9WwErhl6x9XMOEBs5x1R1FxuPC29TMJSMeAEnUlkEgbZw6r0FFZ9jFN07eykXAMgNZH3WrZSqxQkj4qKEQ';
        $this->assertTrue(Hash::check($pass, $expected));
    }

    public function test_hash_make_returns_hash()
    {
        $pass = Str::random();
        $hash = Hash::make($pass);

        $this->assertNotSame($pass, $hash);
    }

    public function test_hash_make_output_validates_correctly()
    {
        $pass = Str::random();
        $hash = Hash::make($pass);

        $this->assertTrue(Hash::check($pass, $hash));
    }

    public function test_hasher_generates_different_salt_on_every_run()
    {
        $pass = Str::random();
        $hash1 = Hash::make($pass);
        $hash2 = Hash::make($pass);

        $this->assertNotSame($hash1, $hash2);
        $this->assertTrue(Hash::check($pass, $hash1));
        $this->assertTrue(Hash::check($pass, $hash2));
    }

    public function test_hash_check_returns_false_for_empty_string_hash()
    {
        $hashEmptyPass = Hash::make('');
        $this->assertFalse(Hash::check('', ''));
        $this->assertFalse(Hash::check(Str::random(), ''));
        $this->assertTrue(Hash::check('', $hashEmptyPass));
    }

    public function test_verify_algorithm_disabled_validates_other_algorithms()
    {
        $pass = Str::random();
        $hash = app('hash')->driver('bcrypt')->make($pass);
        $this->assertTrue(Hash::check($pass, $hash));
    }

    public function test_verify_algorithm_enabled_fails_to_validate_other_algorithms()
    {
        $this->app['config']->set('hashing.hmac-bcrypt.verify', true);
        $pass = Str::random(75);
        $hash = app('hash')->driver('bcrypt')->make($pass);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('This password does not use the HMAC-Bcrypt algorithm.');

        Hash::check($pass, $hash);
    }

    public function test_hashing_passwords_longer_than_bcrypt_limit_works()
    {
        // // BCrypt cuts passwords longer than 72
        $pass1 = Str::random(75);
        $pass2 = substr($pass1, 0, strlen($pass1) - 3) . Str::random(3);
        // $hash1 = app('hash')->driver('bcrypt')->make($pass1);
        // $hash2 = app('hash')->driver('bcrypt')->make($pass2);
        // $this->assertTrue(app('hash')->driver('bcrypt')->check($pass1, $hash1));
        // $this->assertTrue(app('hash')->driver('bcrypt')->check($pass2, $hash2));
        // // Bcrypt will validate pass1 with hash2 and viceversa
        // $this->assertTrue(app('hash')->driver('bcrypt')->check($pass1, $hash2));
        // $this->assertTrue(app('hash')->driver('bcrypt')->check($pass2, $hash1));

        // Now let's try with HMAC-Bcrypt
        $hash1 = Hash::make($pass1);
        $hash2 = Hash::make($pass2);
        $this->assertTrue(Hash::check($pass1, $hash1));
        $this->assertTrue(Hash::check($pass2, $hash2));
        // HMAC-Bcrypt will NOT validate pass1 with hash2 or the other way around
        $this->assertFalse(Hash::check($pass1, $hash2));
        $this->assertFalse(Hash::check($pass2, $hash1));

        // Now let's go nuts
        $pass1 = Str::random(1024);
        $pass2 = substr($pass1, 0, strlen($pass1) - 16) . Str::random(16);
        // Now let's try with HMAC-Bcrypt
        $hash1 = Hash::make($pass1);
        $hash2 = Hash::make($pass2);
        $this->assertTrue(Hash::check($pass1, $hash1));
        $this->assertTrue(Hash::check($pass2, $hash2));
        // HMAC-Bcrypt will NOT validate pass1 with hash2
        $this->assertFalse(Hash::check($pass1, $hash2));
        $this->assertFalse(Hash::check($pass2, $hash1));
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

        $this->assertTrue(Hash::needsRehash($hash, [
            'rounds' => $this->app['config']->get('hashing.hmac-bcrypt.rounds') + 1,
        ]));
    }

    public function test_hash_needs_rehash_returns_true_for_different_algo()
    {
        $pass = Str::random();
        $hash = app('hash')->driver('bcrypt')->make($pass);

        $this->assertTrue(Hash::needsRehash($hash));
    }

    public function test_hash_needs_rehash_returns_true_for_different_algo_same_id()
    {
        $pass = Str::random();
        $hash = crypt($pass, '$2a$07$usesomesillystringforsalt$');

        $this->assertTrue(Hash::needsRehash($hash));
    }

    public function test_hash_with_wrong_alphabet_throws_exception()
    {
        $pass = Str::random();
        $hash = Hash::make($pass);

        [, , , $actualHash] = explode('$', $hash);
        $salt = substr($actualHash, 0, HmacBcryptHasher::BCRYPT_SALT_CHARS);

        $badHash = str_replace($salt, Str::repeat('*', HmacBcryptHasher::BCRYPT_SALT_CHARS), $hash);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Invalid salt provided');

        Hash::check($pass, $badHash);
    }

    public function test_hash_with_little_number_rounds_throws_exception()
    {
        $pass = Str::random();

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Invalid number of rounds');

        Hash::make($pass, ['rounds' => 3]);
    }

    public function test_hash_with_too_many_rounds_throws_exception()
    {
        $pass = Str::random();

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Invalid number of rounds');

        Hash::make($pass, ['rounds' => 32]);
    }

    public function test_changing_pepper_on_runtime_changes_output()
    {
        /** @var \j3j5\HmacBcryptLaravel\HashManager */
        $manager = $this->app['hash'];
        /** @var \j3j5\HmacBcryptLaravel\HmacBcryptHasher $hasher */
        $hasher = $manager->driver();
        $pass = Str::random();
        $hashDefaultPepper = $hasher->make($pass);
        $hashRedPepper = $hasher->setPepper('red-pepper')->make($pass);

        /** @var \j3j5\HmacBcryptLaravel\HmacBcryptHasher $defaultHasher */
        $defaultHasher = $manager->createHmacBcryptDriver(); // Create a new default driver

        // default driver works for normal hash, fails with red-peppered one
        $this->assertTrue($defaultHasher->check($pass, $hashDefaultPepper));
        $this->assertFalse($defaultHasher->check($pass, $hashRedPepper));

        // red-pepper driver fails for normal hash, works with red-peppered one
        $this->assertFalse($hasher->check($pass, $hashDefaultPepper));
        $this->assertTrue($hasher->check($pass, $hashRedPepper));
    }

    public function test_changing_rounds_on_runtime_changes_output_but_still_validates()
    {
        /** @var \j3j5\HmacBcryptLaravel\HashManager */
        $manager = $this->app['hash'];
        /** @var \j3j5\HmacBcryptLaravel\HmacBcryptHasher $hasher */
        $hasher = $manager->driver();
        $pass = Str::random();
        $defaultRounds = $this->app['config']->get('hashing.hmac-bcrypt.rounds');

        $hashDefaultRounds = $hasher->make($pass);
        $hashDifferentRounds = $hasher->setRounds($defaultRounds - 1)->make($pass);

        $this->assertNotEmpty($hashDefaultRounds, $hashDifferentRounds);

        [, , $outputCostDefault] = explode('$', $hashDefaultRounds);
        $this->assertEquals($defaultRounds, $outputCostDefault);

        [, , $outputCostDifferent] = explode('$', $hashDifferentRounds);
        $this->assertEquals($defaultRounds - 1, $outputCostDifferent);

        // No matter what cost (rounds) is defined on the hasher, the check function
        // should work just the same
        /** @var \j3j5\HmacBcryptLaravel\HmacBcryptHasher $defaultHasher */
        $defaultHasher = $manager->createHmacBcryptDriver();
        $this->assertTrue($defaultHasher->check($pass, $hashDefaultRounds));
        $this->assertTrue($defaultHasher->check($pass, $hashDifferentRounds));

        $this->assertTrue($hasher->check($pass, $hashDefaultRounds));
        $this->assertTrue($hasher->check($pass, $hashDifferentRounds));
    }

    public function test_info_function_works_for_different_inputs()
    {
        $pass = Str::random();

        $hash = Hash::make($pass);
        $info = Hash::info($hash);
        $this->assertSame(HmacBcryptHasher::ALGO_NAME, $info['algoName']);

        $bcryptHash = app('hash')->driver('bcrypt')->make($pass);
        $infoBcrypt = Hash::info($bcryptHash);
        $this->assertSame('bcrypt', $infoBcrypt['algoName']);

        $argonHash = app('hash')->driver('argon')->make($pass);
        $infoArgon = Hash::info($argonHash);
        $this->assertSame(PASSWORD_ARGON2I, $infoArgon['algoName']);

        $infoInvalid = Hash::info('$2y$07$usesomesillystringfors');
        $this->assertSame('unknown', $infoInvalid['algoName']);
    }

    public function test_the_hasher_does_not_work_without_pepper()
    {
        $this->app['config']->set('hashing.hmac-bcrypt.pepper', '');
        $pass = Str::random();

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage("HMAC-Bcrypt can't work without pepper and is currently empty.");

        Hash::make($pass);
    }

    public function test_the_hasher_does_not_let_you_set_empty_pepper()
    {
        $driver = $this->app['hash.driver'];

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage("HMAC-Bcrypt can't work without pepper.");

        $driver->setPepper('');
    }

    public function test_passing_salt_as_option_gets_ignored()
    {
        $pass = Str::random();
        $salt = 'pinksalt';
        $hash = Hash::make($pass, ['salt' => $salt]);
        $this->assertFalse(strpos($hash, $salt));
    }

    public function test_empty_config_uses_valid_default_options()
    {
        $this->app['config']->set('hashing.hmac-bcrypt', null);

        // Pepper is needed
        $this->app['config']->set('hashing.hmac-bcrypt.pepper', Str::random());
        $pass = Str::random();
        $hash = Hash::make($pass);

        $this->assertTrue(Hash::check($pass, $hash));
    }
}
