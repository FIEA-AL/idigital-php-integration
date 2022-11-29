<?php

namespace Fiea\classes;

class IDigitalConfig {
    public string $issuer;
    public string $clientId;
    public array $scopes = [];
    public ?string $grantType;
    public ?string $redirectUri;
    public ?string $responseType;
    public string $applicationHost;
    public ?string $applicationType;
    public ?string $codeChallengeMethod;
    public ?string $postLogoutRedirectUri;
    public ?string $tokenEndpointAuthMethod;

    public function __construct($configs) {
        $this->issuer = $configs['issuer'];
        $this->clientId = $configs['clientId'];
        $this->redirectUri = $configs['redirectUri'];
        $this->applicationHost = $configs['applicationHost'];
        $this->responseType = $configs['responseType'] ?? 'code';
        $this->applicationType = $configs['applicationType'] ?? 'web';
        $this->grantType = $configs['grantType'] ?? 'authorization_code';
        $this->scopes = $configs['scopes'] ?? ['openid', 'profile', 'email'];
        $this->codeChallengeMethod = $configs['codeChallengeMethod'] ?? 'S256';
        $this->tokenEndpointAuthMethod = $configs['tokenEndpointAuthMethod'] ?? 'none';
        $this->postLogoutRedirectUri = $configs['postLogoutRedirectUri'] ?? $this->issuer;
    }
}
