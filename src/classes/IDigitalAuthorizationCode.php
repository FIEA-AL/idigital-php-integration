<?php

namespace Fiea\classes;
use Fiea\interfaces\IIDigitalSession;
use Fiea\IDigital;
use Exception;
use stdClass;

class IDigitalAuthorizationCode {
    private IDigital $idigital;
    public array $configs;

    public function __construct(IDigital $idigital) {
        $this->configs = IDigitalConfig::getAuthorizationCodeConfig($idigital->options);
        $this->idigital = $idigital;
    }

    /**
     * @throws Exception
     */
    public function authorize(?IIDigitalSession $session = null): string {
        $authorizationEndpoint = $this->idigital->discovery->authorization_endpoint;
        $pkceKeysPair = IDigitalHelp::getPkceKeysPair();
        $nonce = IDigitalHelp::getRandomBytes();
        $state = IDigitalHelp::getRandomBytes();

        // Update session object with provider response
        $IDigitalSession = $this->idigital->getSession($session);
        $IDigitalSession->put('codeChallenge', $pkceKeysPair->codeChallenge);
        $IDigitalSession->put('codeVerifier', $pkceKeysPair->codeVerifier);
        $IDigitalSession->put('nonce', $nonce);
        $IDigitalSession->put('state', $state);

        return IDigitalHelp::getParameterizedUrl($authorizationEndpoint, [
            ['code_challenge_method', $this->configs['codeChallengeMethod']],
            ['code_challenge', $pkceKeysPair->codeChallenge],
            ['response_type', $this->configs['responseType']],
            ['redirect_uri', $this->configs['redirectUri']],
            ['resource', $this->configs['applicationHost']],
            ['scope', join('+', $this->configs['scopes'])],
            ['client_id', $this->configs['clientId']],
            ['nonce', $nonce],
            ['state', $state]
        ]);
    }

    /**
     * @throws IDigitalException
     */
    public function callback(string $code, string $issuer, string $state, ?IIDigitalSession $session = null): object {
        $IDigitalSession = $this->idigital->getSession($session);

        if ($issuer !== $this->configs['issuer']) {
            $message = IDigitalMessage::$DIVERGENT_ISSUER;
            throw new IDigitalException(400, $message);
        }

        if ($state !== $IDigitalSession->get('state')) {
            $message = IDigitalMessage::$DIVERGENT_STATE;
            throw new IDigitalException(400, $message);
        }

        $object = new stdClass();
        $nonce = $IDigitalSession->get('nonce');
        $tokens = $this->getTokens($code, $IDigitalSession);
        $object->idToken = IDigitalIDToken::verify($tokens->id_token, $nonce, $this->idigital->jwks, $this->configs);
        $object->accessToken = IDigitalAccessToken::verify($tokens->access_token, $this->idigital->jwks, $this->configs);

        // Update session object with provider response
        $IDigitalSession->put('accessToken', $tokens->access_token);
        $IDigitalSession->put('idToken', $tokens->id_token);
        $IDigitalSession->put('code', $code);
        return $object;
    }

    public function isAuthenticated(?IIDigitalSession $session = null): object {
        return $this->idigital->isAuthenticated($this->configs, $session);
    }

    /**
     * @throws IDigitalException
     */
    public function logout(?IIDigitalSession $session = null, ?callable $afterSessionDestroyFn = null): string {
        return $this->idigital->logout($this->configs, $session, $afterSessionDestroyFn);
    }

    /**
     * @throws IDigitalException
     */
    private function getTokens(string $code, ?IIDigitalSession $session = null): object {
        $tokenEndpoint = $this->idigital->discovery->token_endpoint;
        $IDigitalSession = $this->idigital->getSession($session);

        $body = IDigitalHelp::getParameterizedUrl($tokenEndpoint, [
            ['code_challenge_method', $this->configs['codeChallengeMethod']],
            ['code_challenge', $IDigitalSession->get('codeChallenge')],
            ['code_verifier', $IDigitalSession->get('codeVerifier')],
            ['redirect_uri', $this->configs['redirectUri']],
            ['resource', $this->configs['applicationHost']],
            ['grant_type', $this->configs['grantType']],
            ['client_id', $this->configs['clientId']],
            ['nonce', $IDigitalSession->get('nonce')],
            ['code', $code]
        ]);

        return IDigitalHttp::getTokens($tokenEndpoint, $body);
    }
}