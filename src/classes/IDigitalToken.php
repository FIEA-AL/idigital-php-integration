<?php

namespace Fiea\classes;

class IDigitalToken {
    /**
     * @throws IDigitalException
     */
    protected static function getHeader(?string $token, string $typ): ?object {
        $header = self::getData($token, 0);

        if (empty($header->alg) || $header->alg != 'RS256') {
            $message = IDigitalMessage::$JWT_WITHOUT_ALG;
            throw new IDigitalException(400, $message);
        }

        if (empty($header->typ) || $header->typ != $typ) {
            $message = IDigitalMessage::$JWT_WITHOUT_TYP;
            throw new IDigitalException(400, $message);
        }

        return $header;
    }

    /**
     * @throws IDigitalException
     */
    protected static function getPayload(?string $token): ?object {
        return self::getData($token, 1);
    }

    /**
     * @throws IDigitalException
     */
    protected static function getSignature(?string $token): ?object {
        return self::getData($token, 2);
    }

    /**
     * @throws IDigitalException
     */
    protected static function isNotJWT(): void {
        $message = IDigitalMessage::$INVALID_JWT;
        throw new IDigitalException(400, $message);
    }

    /**
     * @throws IDigitalException
     */
    protected static function getPublicKeyByKid(string $kid, string $alg, $keys): ?object {
        $publicKey = null;

        foreach ($keys->keys as $value) {
            if ($value->kid != null && $value->alg != null) {
                if ($value->kid == $kid && $value->alg == $alg) {
                    $publicKey = $value;
                    break;
                }
            }
        }

        if (empty($kid) || $publicKey == null) {
            $message = IDigitalMessage::$JWT_WITHOUT_KID;
            throw new IDigitalException(400, $message);
        }

        return $publicKey;
    }

    /**
     * @throws IDigitalException
     */
    protected static function verifyIssuer(string $value1, string $value2): void {
        self::verifyAttributesOfJWT($value1, $value2, IDigitalMessage::$DIVERGENT_ISSUER);
    }

    /**
     * @throws IDigitalException
     */
    protected static function verifyClient(string $value1, string $value2): void {
        self::verifyAttributesOfJWT($value1, $value2, IDigitalMessage::$DIVERGENT_CLIENT_ID);
    }

    /**
     * @throws IDigitalException
     */
    protected static function verifyAudience(string $value1, string $value2): void {
        self::verifyAttributesOfJWT($value1, $value2, IDigitalMessage::$DIVERGENT_AUDIENCE);
    }

    /**
     * @throws IDigitalException
     */
    protected static function verifyNonce(string $value1, string $value2): void {
        self::verifyAttributesOfJWT($value1, $value2, IDigitalMessage::$DIVERGENT_NONCE);
    }

    /**
     * @throws IDigitalException
     */
    private static function verifyAttributesOfJWT(string $value1, string $value2, string $message): void {
        if ($value1 == null || $value2 == null || $value1 != $value2) {
            throw new IDigitalException(400, $message);
        }
    }

    /**
     * @throws IDigitalException
     */
    private static function getData(?string $token, int $offset): ?object {
        if ($token !== null && IDigitalHelp::isJWT($token)) {
            $header = array_slice(explode('.', $token), $offset, 1);
            $header = base64_decode(array_pop($header));
            return json_decode($header);
        }

        self::isNotJWT();
    }
}