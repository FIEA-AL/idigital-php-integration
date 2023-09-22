<?php

namespace Fiea\classes;
use Fiea\interfaces\IIDigitalSession;
use Fiea\IDigital;
use Exception;
use stdClass;

class IDigitalImplicit {
    private IDigital $idigital;
    public array $configs;

    public function __construct(IDigital $idigital) {
        $this->configs = IDigitalConfig::getImplicitConfig($idigital->options);
        $this->idigital = $idigital;
    }

    /**
     * @throws Exception
     */
    public function authorize(?IIDigitalSession $session = null): string {
        $authorizationEndpoint = $this->idigital->discovery->authorization_endpoint;
        $nonce = IDigitalHelp::getRandomBytes();
        $state = IDigitalHelp::getRandomBytes();

        // Update session object with provider response
        $IDigitalSession = $this->idigital->getSession($session);
        $IDigitalSession->put('nonce', $nonce);
        $IDigitalSession->put('state', $state);

        return IDigitalHelp::getParameterizedUrl($authorizationEndpoint, [
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
    public function callback(array $params = null, string $hash = null, ?IIDigitalSession $session = null): object {
        $IDigitalSession = $this->idigital->getSession($session);
        $params = $params ?? $this->getParamsByHash($hash);

        if ($params['state'] !== $IDigitalSession->get('state')) {
            $message = IDigitalMessage::$DIVERGENT_STATE;
            throw new IDigitalException(400, $message);
        }

        $object = new stdClass();
        $nonce = $IDigitalSession->get('nonce');
        $object->idToken = IDigitalIDToken::verify($params['id_token'], $nonce, $this->idigital->jwks, $this->configs);
        $object->accessToken = IDigitalAccessToken::verify($params['access_token'], $this->idigital->jwks, $this->configs);

        // Update session object with provider response
        $IDigitalSession->put('accessToken', $params['access_token']);
        $IDigitalSession->put('idToken', $params['id_token']);
        $object->status = true;
        return $object;
    }

    private function getParamsByHash(string $hash): array {
        $index = strpos($hash, '#');
        $params = [];

        $str = $index === false ? '' : substr($hash, $index + 1);
        parse_str($str, $params);
        return $params;
    }
}