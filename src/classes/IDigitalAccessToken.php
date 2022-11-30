<?php

namespace Fiea\classes;
use Fiea\classes\IDigitalHelp;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use stdClass;

class IDigitalAccessToken extends IDigitalToken {
    public object $payload;
    public object $header;
    public string $token;

    private function __construct(string $token, $jwt) {
        $this->payload = $jwt->payload;
        $this->header = $jwt->header;
        $this->token = $token;
    }

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