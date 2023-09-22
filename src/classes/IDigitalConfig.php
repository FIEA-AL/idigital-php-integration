<?php

namespace Fiea\classes;

class IDigitalConfig {
    public static function getAuthorizationCodeConfig(IDigitalOptions $options): array {
        return array_merge($options->getOptions(), [
            'tokenEndpointAuthMethod' => 'none',
            'grantType' => 'authorization_code',
            'codeChallengeMethod' => 'S256',
            'applicationType' => 'web',
            'responseType' => 'code',
            'defaultMaxAge' => 86400
        ]);
    }

    public static function getImplicitConfig(IDigitalOptions $options): array {
        return array_merge($options->getOptions(), [
            'tokenEndpointAuthMethod' => 'none',
            'responseType' => 'id_token token',
            'applicationType' => 'web',
            'grantType' => 'implicit',
            'defaultMaxAge' => 86400
        ]);
    }
}