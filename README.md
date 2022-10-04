# hmac-bcrypt

![Coverage Badge](https://gist.githubusercontent.com/j3j5/a143261dcd5d0d9456c01f854eccecd0/raw/badge.svg "PHPUnit coverage")
![PHPStan Badge, it reads "level 9"](https://img.shields.io/badge/PHPStan-level%209-brightgreen.svg?style=flat&logo=php "PHPStan Level 9")
![Build status for "main" branch](https://github.com/j3j5/hmac-bcrypt-laravel/actions/workflows/php.yml/badge.svg?branch=main "Build status")

This repository contains an implementation of the `hmac-bcrypt` password hashing function for the [Laravel Framework](https://github.com/laravel/laravel). It is based on the reference implementation created by [@epixoip]( https://github.com/epixoip ) (specifically [the PHP one](https://github.com/epixoip/hmac-bcrypt/blob/main/php/src/)).

If you are asking yourself why, you can read the [technical justification](https://github.com/epixoip/hmac-bcrypt#justification) on the original implementation.

If you want to use it, you can use composer:

```
composer require j3j5/hmac-bcrypt-laravel
```

Then on your `config/hashing.php` you can change the driver to `hmac-bcrypt`. In order to work, you need to set a _pepper_ which should be a **unique (per project) secret string**. You have two options, either set `HMAC_BCRYPT_PEPPER` on your `.env` or as an environment variable, or add to your own `hashing.php` config file the following array:
```php
'hmac-bcrypt' => [
    'pepper' => 'black-pepper'
],
```

The amount of rounds used by bcrypt is also customizable. You can use `HMAC_BCRYPT_ROUNDS` on your `.env` (or as environment variable) or add the key `rounds` to the `hmac-bcrypt` key on your hashing config.

```php
'hmac-bcrypt' => [
    'rounds' => 15
],
```

Although I tried to be very careful and thorough on the implementation, I made this driver for fun so use at your own risk.