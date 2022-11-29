<?php

namespace Fiea\classes;
use Exception;
use stdClass;

class IDigitalHelp {
    public static function getParameterizedUrl(string $url, array $params): string {
        $queryElement = fn(string $key, string $value) => $key . '=' . $value;
        return $url . '/' . join('&', array_map($queryElement, $params));
	}

    /**
     * @throws Exception
     */
    public static function getRandomBytes(int $bytes = 32): string {
        return rtrim(strtr(base64_encode(bin2hex(random_bytes($bytes))), '+/', '-_'), '=');
	}

    /**
     * @throws Exception
     */
    public static function getPkceKeysPair(): object {
		$codeVerifier = self::getRandomBytes();
        $sha256 = hash('sha256', $codeVerifier, true);
        $codeChallenge = rtrim(strtr(base64_encode($sha256), '+/', '-_'), '=');

        $pkce = new stdClass;
        $pkce->codeVerifier = $codeVerifier;
        $pkce->codeChallenge = $codeChallenge;
        return $pkce;
    }
}