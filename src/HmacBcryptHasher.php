<?php

namespace j3j5\HmacBcryptLaravel;

use Illuminate\Contracts\Hashing\Hasher as HasherContract;
use Illuminate\Hashing\AbstractHasher;
use RuntimeException;

class HmacBcryptHasher extends AbstractHasher implements HasherContract
{
    protected const BCRYPT_ID = '2a';
    protected const BCRYPT_SALT_BYTES = 16;

    // The base64 encoded output of an hmac-sha512
    protected const POST_HASH_LENGTH = 88;

    /**
     * A string for mapping an int to the corresponding radix 64 character.
     */
    public const ITOA64 = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

    /**
     * A 16 bytes string radix64-encoded will be 22 chars
     */
    public const BCRYPT_SALT_CHARS = 22;

    public const ALGO_NAME = 'hmac-bcrypt';
    public const HMAC_HASH_ALGO = 'SHA512';

    /**
     * Indicates whether to perform an algorithm check.
     *
     * @var bool
     */
    protected bool $verifyAlgorithm = false;

    /**
     * The default cost factor.
     *
     * @var int
     */
    protected int $rounds = 13;

    /**
     * The pepper to be applied on the hmac steps
     * @var string
     */
    protected string $pepper;

    /**
     * Create a new hasher instance.
     *
     * @param array{rounds?: int, pepper?: string, verify?: bool} $options
     * @return void
     */
    public function __construct(array $options = [])
    {
        $this->verifyAlgorithm = $options['verify'] ?? $this->verifyAlgorithm;
        $this->rounds = $options['rounds'] ?? $this->rounds;

        $this->pepper = $options['pepper'] ?? '';
        if ($this->pepper === '') {
            throw new RuntimeException("HMAC-Bcrypt can't work without pepper and is currently empty.");
        }
    }

    /**
     * Get information about the given hashed value.
     *
     * @param  string  $hashedValue
     * @return array{algo:null|int|string, algoName:string, options:array{cost?:int, salt?: string, memory_cost?: int, time_cost?: int, threads?: int}}
     */
    public function info($hashedValue) : array
    {
        // Try first the parent
        /** @var array{algo:null|int|string, algoName:string, options:array{cost?:int, salt?: string, memory_cost?: int, time_cost?: int, threads?: int}} $info */
        $info = parent::info($hashedValue);
        // parent::info() - that is, password_get_info(), returns 0 or null for
        // algo for unknown hashes
        if ($info['algo'] !== null && $info['algo'] !== 0) {
            return $info;
        }

        // Try "manually" for our algo
        $settings = explode('$', $hashedValue);
        if (!is_array($settings) || count($settings) !== 4) {
            return $info;
        }

        [,$algoId, $rounds, $hash] = $settings;

        // Bcrypt ID should match
        if ($algoId !== self::BCRYPT_ID) {
            return $info;
        }

        // Length should match, the provided hash (last part of the dollar-separated string)
        // must be the lenght of the salt + the base64 encoded output from sha512,
        // which can have up to 3 padding '=' chars
        $maxLength = self::BCRYPT_SALT_CHARS + self::POST_HASH_LENGTH;
        if (
            strlen($hash) < $maxLength - 3 ||
            strlen($hash) > $maxLength
        ) {
            return $info;
        }

        // Follow the format of password_get_info() array
        $info['algo'] = self::BCRYPT_ID;
        $info['algoName'] = self::ALGO_NAME;
        if (is_numeric($rounds)) {
            $info['options']['cost'] = (int) $rounds;
        }

        return $info;
    }

    /**
     * Hash the given value.
     *
     * @param  string  $value
     * @param  array{rounds?: int, pepper?: string} $options
     * @throws \RuntimeException
     * @return string
     *
     */
    public function make($value, array $options = []) : string
    {
        // Make sure no salt is passed ever on make()
        // Ignore phpstan error so it's not documented that salt could be passed
        unset($options['salt']);    /** @phpstan-ignore-line */

        return $this->hash($value, $options);
    }

    /**
     * Hash the given value.
     *
     * @param  string  $value
     * @param  array{rounds?: int, salt?: string, pepper?: string} $options
     * @throws \RuntimeException
     * @return string
     *
     */
    private function hash($value, array $options = []) : string
    {
        $settings = sprintf(
            '$%2s$%02d$%s',
            self::BCRYPT_ID,
            $this->cost($options),
            $this->salt($options)
        );

        // Pre-hashing is employed to enable input lengths greater than bcrypt's
        // maximum of 72 input bytes.
        $preHash = base64_encode(
            hash_hmac(self::HMAC_HASH_ALGO, $value, $this->pepper($options), true)
        );

        /*
            hmac_sha512_base64 produces 88 bytes of data, while bcrypt has a maximum
            input size of 72 bytes. This is not an issue, and in fact is preferred
            over utilizing a hash algorithm that produces less input data such as
            sha256. We want to fill all 72 bytes, and no security is lost when
            truncating sha512 to 432 bits (this is greater than the 384 bits that
            sha384 provides.)
        */
        $midHash = crypt($preHash, $settings);

        // From phpdocs on crypt():
        // Returns the hashed string or a string that is shorter than 13 characters
        // and is guaranteed to differ from the salt on failure.
        if (strlen($midHash) < 13) {
            throw new RuntimeException('Invalid settings provided to crypt');
        }

        // Post-hashing is employed largely to differentiate hmac-bcrypt hashes
        // from bcrypt hashes i.e., the lengths will differ -- but also to add an
        // extra layer of protection due to the pepper.
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
     * @param  array{rounds?: int, salt?: string, pepper?: string} $options
     * @throws \RuntimeException
     * @return bool
     *
     */
    public function check($value, $hashedValue, array $options = []) : bool
    {
        $algoName = $this->info($hashedValue)['algoName'];
        if ($algoName !== self::ALGO_NAME) {
            if ($this->verifyAlgorithm) {
                throw new RuntimeException('This password does not use the HMAC-Bcrypt algorithm.');
            }
            return parent::check($value, $hashedValue, $options);
        }

        // Retrieve options from the hashedValue
        [, , $rounds, $hash] = explode('$', $hashedValue);
        $salt = substr($hash, 0, self::BCRYPT_SALT_CHARS);

        $options = array_merge($options, [
            'salt' => $salt,
            'rounds' => (int) $rounds,
        ]);

        return hash_equals(
            $this->hash($value, $options),
            $hashedValue
        );
    }

    /**
     * Check if the given hash has been hashed using the given options.
     *
     * @param  string  $hashedValue
     * @param  array{rounds?: int, salt?: string, pepper?: string} $options  $options
     * @return bool
     */
    public function needsRehash($hashedValue, array $options = []) : bool
    {
        $info = $this->info($hashedValue);

        $algo = $info['algo'];
        if ($algo !== self::BCRYPT_ID) {
            return true;
        }

        $algoName = $info['algoName'];
        if ($algoName !== self::ALGO_NAME) {
            return true;
        }
        // info() returns the rounds on the key 'cost' to keep compatibility with
        // the format used by password_get_info()
        $hashCost = $info['options']['cost'] ?? -1;

        return $hashCost !== $this->cost($options);
    }

    /**
     * Set the default password work factor.
     *
     * @param  int  $rounds
     * @return $this
     */
    public function setRounds(int $rounds) : self
    {
        $this->rounds = (int) $rounds;

        return $this;
    }

    /**
     * Verifies that the configuration is less than or equal to what is configured.
     *
     * @internal
     */
    public function verifyConfiguration($value)
    {
        return $this->isUsingCorrectAlgorithm($value) && $this->isUsingValidOptions($value);
    }

    /**
     * Verify the hashed value's algorithm.
     *
     * @param  string  $hashedValue
     * @return bool
     */
    protected function isUsingCorrectAlgorithm($hashedValue)
    {
        return $this->info($hashedValue)['algoName'] === self::ALGO_NAME;
    }

    /**
     * Verify the hashed value's options.
     *
     * @param  string  $hashedValue
     * @return bool
     */
    protected function isUsingValidOptions($hashedValue)
    {
        ['options' => $options] = $this->info($hashedValue);

        if (!is_int($options['cost'] ?? null)) {
            return false;
        }

        if ($options['cost'] > $this->rounds) {
            return false;
        }

        return true;
    }

    /**
     * Extract the cost value from the options array.
     *
     * The two digit cost parameter is the base-2 logarithm of the iteration
     * count for the underlying Blowfish-based hashing algorithm and must be
     * in range 04-31, values outside this range will cause crypt() to fail.
     *
     * @param  array{rounds?: int}  $options
     * @return int<4, 31>
     * @see CRYPT_BLOWFISH @ https://www.php.net/manual/en/function.crypt.php
     */
    protected function cost(array $options = []) : int
    {
        $rounds = $options['rounds'] ?? $this->rounds;
        if ($rounds < 4 || $rounds > 31) {
            throw new RuntimeException('Invalid number of rounds');
        }

        return (int) $rounds;
    }

    /**
     * Salt must be 22 characters from the alphabet "./0-9A-Za-z".
     * Using characters outside of this range in the salt will cause crypt()
     * to return a zero-length string.
     *
     * @param array{salt?: string} $options
     * @throws \RuntimeException
     * @return string
     * @see CRYPT_BLOWFISH @ https://www.php.net/manual/en/function.crypt.php
     */
    protected function salt(array $options = []) : string
    {
        $salt = $options['salt'] ?? $this->radix64Encode(
            random_bytes(self::BCRYPT_SALT_BYTES)
        );

        if (strlen($salt) !== self::BCRYPT_SALT_CHARS) {
            throw new RuntimeException('Salt should be ' . self::BCRYPT_SALT_CHARS . ' chars long');
        }

        $crypt_blowfish_alphabet = '/(?:[\.\/0-9A-Za-z]){' . self::BCRYPT_SALT_CHARS . '}/';
        if (!preg_match($crypt_blowfish_alphabet, $salt)) {
            throw new RuntimeException('Invalid salt provided');
        }

        return $salt;
    }

    /**
     *
     * @param string $pepper
     * @return $this
     */
    public function setPepper(string $pepper) : self
    {
        if ($pepper === '') {
            throw new RuntimeException("HMAC-Bcrypt can't work without pepper.");
        }

        $this->pepper = $pepper;

        return $this;
    }

    /**
     *
     * @param array{pepper?: string} $options
     * @return string
     */
    protected function pepper(array $options = []) : string
    {
        return $options['pepper'] ?? $this->pepper;
    }

    /**
     * This function was derived from the Portable PHP password hashing framework
     * (phpass), written by Solar Designer <solar at openwall.com> in 2004-2006
     * and placed in the public domain.
     * @param string $input
     * @return string
     */
    private function radix64Encode(string $input) : string
    {
        $output = '';
        $i = 0;

        do {
            $c1 = ord($input[$i++]);
            $output .= self::ITOA64[$c1 >> 2];
            $c1 = ($c1 & 0x03) << 4;

            if ($i >= self::BCRYPT_SALT_BYTES) {
                $output .= self::ITOA64[$c1];
                break;
            }

            $c2 = ord($input[$i++]);
            $c1 |= $c2 >> 4;
            $output .= self::ITOA64[$c1];
            $c1 = ($c2 & 0x0f) << 2;

            $c2 = ord($input[$i++]);
            $c1 |= $c2 >> 6;
            $output .= self::ITOA64[$c1];
            $output .= self::ITOA64[$c2 & 0x3f];
        } while (1);

        return $output;
    }
}
