<?php

namespace j3j5\HmacBcryptLaravel;

use Illuminate\Contracts\Hashing\Hasher as HasherContract;
use Illuminate\Hashing\AbstractHasher;
use RuntimeException;

class HmacBcryptHasher extends AbstractHasher implements HasherContract
{
    public const ALGO_NAME = 'hmacbcrypt';
    public const BCRYPT_ID = '2a';
    public const BCRYPT_SALT_BYTES = 16;
    /**
     * A 16 bytes string radix64-encoded will be 22 chars
     */
    public const BCRYPT_SALT_CHARS = 22;

    /**
     * The default cost factor.
     *
     * @var int
     */
    protected $rounds = 10;

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
    protected $hmac_sha = "SHA512";

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

        if (strlen($this->salt) !== self::BCRYPT_SALT_CHARS) {
            throw new RuntimeException("Salt should be " . self::BCRYPT_SALT_CHARS . ' chars long');
        }

        $this->pepper = $options['pepper'] ?? 'Salt-N-Pepa';
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
        if (!is_array($settings)) {
            return $info;
        }

        $info['algo'] = $settings[0];
        $info['algoName'] = $settings[0] === self::BCRYPT_ID ? self::ALGO_NAME : 'unknown';
        if (isset($settings[1]) && is_numeric($settings[1])) {
            $info['options']['cost'] = $settings[1];
        }

        return $info;
    }

    /**
     * Hash the given value.
     *
     * @param  string  $value
     * @param  array  $options
     * @return string
     *
     * @throws \RuntimeException
     */
    public function make($value, array $options = [])
    {
        $settings = sprintf('$%2s$%02d$%s', self::BCRYPT_ID, $this->cost($options), $this->salt($options));

        $preHash  = base64_encode(
            hash_hmac($this->hmac_sha, $value, $this->pepper($options), true)
        );

        $midHash = crypt($preHash, $settings);

        if ($midHash === null) {
            throw new RuntimeException('Bcrypt hashing not supported.');
        }

        $postHash = base64_encode(
            hash_hmac($this->hmac_sha, $midHash, $this->pepper($options), true)
        );

        return $settings . rtrim($postHash, '=');
    }

    /**
     * Check the given plain value against a hash.
     *
     * @param  string  $value
     * @param  string  $hashedValue
     * @param  array  $options
     * @return bool
     *
     * @throws \RuntimeException
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
        $hashCost = $info['options']['cost'] ?? -1;

        return $hashCost !== $this->cost($options['cost']);
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

    public function setSalt(string $salt): self
    {
        $this->salt = $salt;

        return $this;
    }

    protected function salt(array $options = [])
    {
        return $options['salt'] ?? $this->salt;
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
