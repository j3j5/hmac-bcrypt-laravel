<?php

return [

    'hmac-bcrypt' => [
        'pepper' => env('HMAC_BCRYPT_PEPPER'),
        'rounds' => env('HMAC_BCRYPT_ROUNDS', 13),
    ],
];
