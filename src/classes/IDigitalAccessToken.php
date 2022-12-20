<?php

namespace Fiea\classes;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use stdClass;

class IDigitalAccessToken extends IDigitalToken {
    /**
     * @throws IDigitalException
     */
    public static function verify(?string $token, $keys, $options): ?object {
        if ($token !== null && IDigitalHelp::isJWT($token)) {
            $header = self::getHeader($token, 'at+jwt');
            $kid = $header->kid;
            $alg = $header->alg;

            $publicKey = self::getPublicKeyByKid($kid, $alg, $keys);
            $jwk = JWK::parseKey((array) $publicKey);
            $payload = JWT::decode($token, $jwk);

            self::verifyAudience($payload->aud, $options->applicationHost);
            self::verifyClient($payload->client_id, $options->clientId);
            self::verifyIssuer($payload->iss, $options->issuer);

            $object = new stdClass();
            $object->header = $header;
            $object->payload = $payload;

            return new IDigitalAccessToken($token, $object);
        }

        self::isNotJWT();
    }
}