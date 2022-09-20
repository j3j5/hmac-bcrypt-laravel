<?php

namespace j3j5\HmacBcryptLaravel;

use Illuminate\Contracts\Hashing\Hasher as HasherContract;
use Illuminate\Hashing\AbstractHasher;
use RuntimeException;

class HmacBcryptHasher extends AbstractHasher implements HasherContract
{
    protected const ALGO_NAME = 'hmacbcrypt';
    protected const BCRYPT_ID = '2a';
    protected const BCRYPT_SALT_BYTES = 16;

    // The base64 encoded output of an hmac-sha512
    protected const POST_HASH_LENGTH = 88;

    /**
     * A 16 bytes string radix64-encoded will be 22 chars
     */
    public const BCRYPT_SALT_CHARS = 22;

    public const HMAC_HASH_ALGO = 'SHA512';

    /**
     * The default cost factor.
     *
     * @var int
     */
    protected $rounds = 13;

    /**
     * Indicates whether to perform an algorithm check.
     *
     * @var bool
     */
    protected $verifyAlgorithm = false;

    /**
     * The salt to be applied on the bcrypt step
     * @var string
     */
    protected $salt;

    /**
     * The pepper to be applied on the hmac steps
     * @var string
     */
    protected $pepper;

    /**
     *
     * @var string
     */

    /**
     * Create a new hasher instance.
     *
     * @param  array  $options
     * @return void
     */
    public function __construct(array $options = [])
    {
        $this->rounds = $options['rounds'] ?? $this->rounds;
        $this->verifyAlgorithm = $options['verify'] ?? $this->verifyAlgorithm;
        $this->salt = $options['salt'] ?? Radix64::encode(
            random_bytes(self::BCRYPT_SALT_BYTES)
        );

        $this->pepper = $options['pepper'] ?? '';
    }

    /**
     * Get information about the given hashed value.
     *
     * @param  string  $hashedValue
     * @return array
     */
    public function info($hashedValue)
    {
        // Try first the parent
        $info = parent::info($hashedValue);
        if ($info['algo'] !== null || $info['algo'] === 0) {
            return $info;
        }

        // Try "manually" for our algo
        $settings = explode('$', $hashedValue);
        if (!is_array($settings) || count($settings) !== 4) {
            return $info;
        }

        // Bcrypt ID should match
        if ($settings[1] !== self::BCRYPT_ID) {
            return $info;
        }

        // Length should match, the provided hash (last part of the dollar separated string)
        // must be the lenght of the salt + the base64 encoded output from sha512,
        // which can have up to 3 padding '=' chars
        if (
            strlen($settings[3]) < self::BCRYPT_SALT_CHARS + self::POST_HASH_LENGTH - 3 ||
            strlen($settings[3]) > self::BCRYPT_SALT_CHARS + self::POST_HASH_LENGTH
        ) {
            return $info;
        }

        $info['algo'] = self::BCRYPT_ID;
        $info['algoName'] = self::ALGO_NAME;
        if (isset($settings[2]) && is_numeric($settings[2])) {
            $info['options']['cost'] = $settings[2];
        }

        return $info;
    }

    /**
     * Hash the given value.
     *
     * @param  string  $value
     * @param  array  $options
     * @throws \RuntimeException
     * @return string
     *
     */
    public function make($value, array $options = [])
    {
        $settings = sprintf('$%2s$%02d$%s', self::BCRYPT_ID, $this->cost($options), $this->salt($options));

        // Pre-hashing is employed to enable input lengths greater than bcrypt's maximum of 72 input bytes.
        $preHash = base64_encode(
            hash_hmac(self::HMAC_HASH_ALGO, $value, $this->pepper($options), true)
        );

        // hmac_sha512_base64 produces 88 bytes of data, while bcrypt has a maximum input size of 72 bytes.
        // This is not an issue, and in fact is preferred over utilizing a hash algorithm that produces
        // less input data such as sha256. We want to fill all 72 bytes, and no security is lost when
        // truncating sha512 to 432 bits (this is greater than the 384 bits that sha384 provides.)
        $midHash = crypt($preHash, $settings);

        if ($midHash === null) {
            throw new RuntimeException('Bcrypt hashing not supported.');
        }

        // Post-hashing is employed largely to differentiate hmac-bcrypt hashes from bcrypt hashes
        // i.e., the lengths will differ -- but also to add an extra layer of protection due to the pepper.
        $postHash = base64_encode(
            hash_hmac(self::HMAC_HASH_ALGO, $midHash, $this->pepper($options), true)
        );

        return $settings . rtrim($postHash, '=');
    }

    /**
     * Check the given plain value against a hash.
     *
     * @param  string  $value
     * @param  string  $hashedValue
     * @param  array  $options
     * @throws \RuntimeException
     * @return bool
     *
     */
    public function check($value, $hashedValue, array $options = [])
    {
        if ($this->verifyAlgorithm && $this->info($hashedValue)['algoName'] !== self::ALGO_NAME) {
            throw new RuntimeException('This password does not use the Hmac-Bcrypt algorithm.');
        }

        if (strlen($hashedValue) === 0) {
            return false;
        }

        // Add options from the hashed value
        [, , $cost, $salt] = explode('$', $hashedValue);
        $salt = substr($salt, 0, self::BCRYPT_SALT_CHARS);
        $options = array_merge($options, [
            'cost' => $cost,
            'salt' => $salt,
        ]);

        return hash_equals(
            $this->make($value, $options),
            $hashedValue
        );
    }

    /**
     * Check if the given hash has been hashed using the given options.
     *
     * @param  string  $hashedValue
     * @param  array  $options
     * @return bool
     */
    public function needsRehash($hashedValue, array $options = [])
    {
        $info = $this->info($hashedValue);
        $algo = $info['algo'] ?? '';
        if ($algo !== self::BCRYPT_ID) {
            return true;
        }

        $algoName = $info['algoName'] ?? '';
        if ($algoName !== self::ALGO_NAME) {
            return true;
        }

        $hashCost = $info['options']['cost'] ?? -1;

        return $hashCost !== $this->cost($options);
    }

    /**
     * Set the default password work factor.
     *
     * @param  int  $rounds
     * @return $this
     */
    public function setRounds($rounds)
    {
        $this->rounds = (int) $rounds;

        return $this;
    }

    /**
     * Extract the cost value from the options array.
     *
     * @param  array  $options
     * @return int
     */
    protected function cost(array $options = [])
    {
        return $options['rounds'] ?? $this->rounds;
    }

    /**
     *
     * @param array<string, string|int> $options
     * @throws \RuntimeException
     * @return string
     */
    protected function salt(array $options = [])
    {
        $salt = $options['salt'] ?? $this->salt;

        if (strlen($salt) !== self::BCRYPT_SALT_CHARS) {
            throw new RuntimeException('Salt should be ' . self::BCRYPT_SALT_CHARS . ' chars long');
        }

        return $salt;
    }

    public function setPepper(string $pepper): self
    {
        $this->pepper = $pepper;

        return $this;
    }

    protected function pepper(array $options = [])
    {
        return $options['pepper'] ?? $this->pepper;
    }
}
