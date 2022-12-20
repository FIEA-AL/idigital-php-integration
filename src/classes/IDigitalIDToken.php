<?php

namespace Fiea\classes;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use stdClass;

class IDigitalIDToken extends IDigitalToken {
    /**
     * @throws IDigitalException
     */
    public static function verify(?string $token, ?string $nonce, $keys, $options): ?object {
        if ($token !== null && $nonce != null && IDigitalHelp::isJWT($token)) {
            $header = self::getHeader($token, 'JWT');
            $kid = $header->kid;
            $alg = $header->alg;

            $publicKey = self::getPublicKeyByKid($kid, $alg, $keys);
            $jwk = JWK::parseKey((array) $publicKey);
            $payload = JWT::decode($token, $jwk);

            self::verifyAudience($payload->aud, $options->clientId);
            self::verifyIssuer($payload->iss, $options->issuer);
            self::verifyNonce($payload->nonce, $nonce);

            $object = new stdClass();
            $object->header = $header;
            $object->payload = $payload;
            return new IDigitalIDToken($token, $object);
        }

        self::verifyNonce($nonce, $nonce);
        self::isNotJWT();
    }
}