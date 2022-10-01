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

    public function test_hash_check_returns_false_for_empty_string()
    {
        $this->assertFalse(Hash::check('', ''));
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

    public function test_hash_needs_rehash_returns_true_for_different_algo_same_id()
    {
        $pass = Str::random();
        $hash = crypt($pass, '$2a$07$usesomesillystringfors');

        $this->assertTrue(Hash::needsRehash($hash));
    }

    public function test_hash_with_wrong_length_custom_salt_throws_exception()
    {
        $pass = Str::random();

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Salt should be ' . HmacBcryptHasher::BCRYPT_SALT_CHARS . ' chars long');

        $hash = Hash::make($pass, ['salt' => 'sweetsalt']);
    }

    public function test_hash_with_wrong_alphabet_throws_exception()
    {
        $pass = Str::random();

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Invalid salt provided');

        $hash = Hash::make($pass, ['salt' => Str::repeat('*', 22)]);
    }

    public function test_hash_with_wrong_number_rounds_throws_exception()
    {
        $pass = Str::random();

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Invalid number of rounds');

        $hash = Hash::make($pass, ['rounds' => 3]);
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

        [, , $outputCostDefault,] = explode('$', $hashDefaultRounds);
        $this->assertEquals($defaultRounds, $outputCostDefault);

        [, , $outputCostDifferent,] = explode('$', $hashDifferentRounds);
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

}
