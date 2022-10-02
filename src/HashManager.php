<?php

namespace j3j5\HmacBcryptLaravel;

use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Hashing\HashManager as Manager;

class HashManager extends Manager implements Hasher
{
    /**
     * Create an instance of the Hmac-Bcrypt hash Driver.
     *
     * @return \j3j5\HmacBcryptLaravel\HmacBcryptHasher
     */
    public function createHmacBcryptDriver()
    {
        $options = $this->config->get('hashing.hmac-bcrypt');
        if (!is_array($options)) {
            $options = [];
        }
        return new HmacBcryptHasher($options);
    }
}
