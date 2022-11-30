<?php

namespace Fiea\classes;
use Fiea\classes\IDigitalHelp;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use stdClass;

class IDigitalIDToken {
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
    public static function verify(?string $token, ?string $nonce, $keys, $options): ?object {
        if ($token !== null && IDigitalHelp::isJWT($token)) {
            $decoded = explode('.', $token);
            $header = array_pop($decoded);
            $header = base64_decode($header);
            $header = json_decode($header);
            $publicKey = null;

            if (empty($header->alg) || $header->alg != 'RS256') {
                $message = IDigitalMessage::$JWT_WITHOUT_ALG;
                throw new IDigitalException(400, $message);
            }

            if (empty($header->typ) || $header->typ != 'JWT') {
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

            if ($payload->aud != $options->clientId) {
                $message = IDigitalMessage::$DIVERGENT_AUDIENCE;
                throw new IDigitalException(400, $message);
            }

            if ($payload->iss != $options->issuer) {
                $message = IDigitalMessage::$DIVERGENT_ISSUER;
                throw new IDigitalException(400, $message);
            }

            if ($payload->nonce !== $nonce) {
                $message = IDigitalMessage::$DIVERGENT_NONCE;
                throw new IDigitalException(400, $message);
            }

            $object = new stdClass();
            $object->header = $header;
            $object->payload = $payload;

            return new IDigitalIDToken($token, $object);
        }

        if ($nonce == null) {
            $message = IDigitalMessage::$DIVERGENT_NONCE;
            throw new IDigitalException(400, $message);
        }

        $message = IDigitalMessage::$INVALID_JWT;
        throw new IDigitalException(400, $message);
    }
}