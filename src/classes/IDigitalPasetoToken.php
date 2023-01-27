<?php

namespace Fiea\classes;
use ParagonIE\Paseto\ProtocolCollection;
use ParagonIE\Paseto\Protocol\Version4;
use ParagonIE\Paseto\Rules\ForAudience;
use ParagonIE\Paseto\Rules\NotExpired;
use ParagonIE\Paserk\Types\PublicType;
use ParagonIE\Paseto\Rules\IssuedBy;
use ParagonIE\Paserk\Types\Pid;
use ParagonIE\Paseto\Parser;
use stdClass;

class IDigitalPasetoToken {
    /**
     * @throws IDigitalException
     */
    public static function verify(?string $token, ?object $keys, $options): ?object {
        if (isset($token) && isset($keys) && isset($options)) {
            $kid = IDigitalPasetoToken::getKidByTokenFooter($token);
            $publicKey = IDigitalPasetoToken::getPublicKeyByKid($kid, $keys);
            $rules = new IDigitalPasetoRules($options->issuer, $options->clientId);
            $decoded = Parser::getPublic($publicKey, ProtocolCollection::v4())->addRule($rules)->parse($token);

            $object = new stdClass();
            $object->payload = $decoded->getClaims();
            $object->footer = $decoded->getFooterArray();
            return $object;
        } else if ($options->useCredentialToken && !isset($token)) {
            $message = IDigitalMessage::$REQUIRED_CREDENTIAL_TOKEN;
            throw new IDigitalException(500, $message);
        } else {
            return null;
        }
    }

    private static function getKidByTokenFooter(string $token): ?string {
        $decoded = json_decode(Parser::extractFooter($token));
        return $decoded->kid;
    }

    /**
     * @throws IDigitalException
     */
    private static function getPublicKeyByKid(string $kid, $keys): ?object {
        $version = new Version4();
        $publicType = new PublicType($version);
        $paserk = null;

        foreach ($keys->keys as $value) {
            $pid = Pid::encode($version, $value);
            if ($pid == $kid) {
                $paserk = $value;
                break;
            }
        }

        if ($paserk == null) {
            $message = IDigitalMessage::$COULD_NOT_FIND_PUBLIC_KEYS;
            throw new IDigitalException(500, $message);
        }

        return $publicType->decode($paserk);
    }
}