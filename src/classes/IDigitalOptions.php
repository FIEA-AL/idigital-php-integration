<?php

namespace Fiea\classes;
use Fiea\interfaces\IIDigitalSession;

class IDigitalOptions {
    public string $issuer;
    public $session = null;
    public string $clientId;
    public array $scopes = [];
    public ?string $redirectUri;
    public ?string $clientSecret;
    public string $applicationHost;
    public ?string $postLogoutRedirectUri;

    public function __construct($configs) {
        $this->issuer = $configs['issuer'];
        $this->clientId = $configs['clientId'];
        $this->redirectUri = $configs['redirectUri'];
        $this->applicationHost = $configs['applicationHost'];
        $this->clientSecret = $configs['clientSecret'] ?? null;
        $this->session = $configs['session'] ?? new IDigitalSession();
        $this->scopes = $configs['scopes'] ?? ['openid', 'profile', 'email'];
        $this->postLogoutRedirectUri = $configs['postLogoutRedirectUri'] ?? $this->issuer;
    }

    public function getOptions(): array {
        return [
            'scopes' => $this->scopes,
            'issuer' => $this->issuer,
            'session' => $this->session,
            'clientId' => $this->clientId,
            'redirectUri' => $this->redirectUri,
            'clientSecret' => $this->clientSecret,
            'applicationHost' => $this->applicationHost,
            'postLogoutRedirectUri' => $this->postLogoutRedirectUri
        ];
    }

    public function getSession(): IIDigitalSession {
        return $this->session ?? $this->session = new IDigitalSession();
    }
}
