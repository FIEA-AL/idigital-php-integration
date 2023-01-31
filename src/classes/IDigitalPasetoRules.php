<?php

namespace Fiea\classes;
use ParagonIE\Paseto\Exception\PasetoException;
use function hash_equals;

class IDigitalPasetoRules implements ValidationRuleInterface {
    private string $failure = 'OK';
    private string $audience;
    private string $issuer;
    private DateTime $now;

    public function __construct(string $issuer, string $audience) {
        $this->now = new DateTime();
        $this->audience = $audience;
        $this->issuer = $issuer;
    }

    public function getFailureMessage(): string {
        return $this->failure;
    }

    public function isValid(JsonToken $token): bool {
        try {
            $attributes = $token->get('attributes');
            $expires = $token->getExpiration();
            $audience = $token->getAudience();
            $issuer = $token->getIssuer();

            if ($expires < $this->now) {
                $this->failure =  IDigitalMessage::$EXPIRED_TOKEN;
                return false;
            }

            if (!hash_equals($this->audience, $audience)) {
                $this->failure = IDigitalMessage::$DIVERGENT_AUDIENCE;
                return false;
            }

            if (!hash_equals($this->issuer, $issuer)) {
                $this->failure = IDigitalMessage::$DIVERGENT_ISSUER;
                return false;
            }

            if (!isset($attributes) || !is_array($attributes)) {
                $this->failure = IDigitalMessage::$REQUIRED_PASETO_ATTRIBUTES;
                return false;
            }
        } catch (PasetoException | Exception $e) {
            $this->failure = $e->getMessage();
            return false;
        }

        return true;
    }
}
