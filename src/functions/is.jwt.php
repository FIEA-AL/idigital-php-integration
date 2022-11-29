<?php

namespace Fiea\functions;

function isJWT(string $input): bool {
    $pattern = '/^([a-zA-Z0-9_=]+)\.([a-zA-Z0-9_=]+)\.([a-zA-Z0-9_\-+\/=]*)/';
    return gettype($input) == 'string' && preg_match($pattern, $input);
}