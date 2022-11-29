<?php

namespace Fiea\classes;
use function Fiea\functions\isJWT;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use stdClass;

class IDigitalAccessToken {
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
        if ($token !== null && isJWT($token)) {
            $decoded = explode('.', $token);
            $header = array_pop($decoded);
            $header = base64_decode($header);
            $header = json_decode($header);
            $publicKey = null;

            if (empty($header->alg) || $header->alg != 'RS256') {
                $message = IDigitalMessage::$JWT_WITHOUT_ALG;
                throw new IDigitalException(400, $message);
            }

            if (empty($header->typ) || $header->typ != 'at+jwt') {
                $message = IDigitalMessage::$JWT_WITHOUT_TYP;
                throw new IDigitalException(400, $message);
            }

            foreach ($keys as $value) {
                if ($value->kid != null && $value->alg != null) {
                    if ($value->kid == $header->kid && $value->alg == $header->alg) {
                        $publicKey = $value;
                        break;
                    }
                }
            }

            if (empty($header->kid) || $publicKey == null) {
                $message = IDigitalMessage::$JWT_WITHOUT_KID;
                throw new IDigitalException(400, $message);
            }

            $jwk = JWK::parseKey($publicKey);
            $payload = JWT::decode($token, $jwk);

            if ($payload->aud != $options->applicationHost) {
                $message = IDigitalMessage::$DIVERGENT_AUDIENCE;
                throw new IDigitalException(400, $message);
            }

            if ($payload->iss != $options->issuer) {
                $message = IDigitalMessage::$DIVERGENT_ISSUER;
                throw new IDigitalException(400, $message);
            }

            if ($payload->client_id !== $options->clientId) {
                $message = IDigitalMessage::$DIVERGENT_CLIENT_ID;
                throw new IDigitalException(400, $message);
            }

            $object = new stdClass();
            $object->header = $header;
            $object->payload = $payload;

            return new IDigitalAccessToken($token, $object);
        }

        $message = IDigitalMessage::$INVALID_JWT;
        throw new IDigitalException(400, $message);
    }
}