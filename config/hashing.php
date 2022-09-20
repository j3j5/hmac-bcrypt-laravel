<?php

return [

    'hmac-bcrypt' => [
        'pepper' => env('HMAC_BCRYPT_PEPPER', 'hmac_bcrypts'),
        'rounds' => env('HMAC_BCRYPT_ROUNDS', 13),
    ],
];