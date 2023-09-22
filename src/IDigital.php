<?php

namespace Fiea;
use Fiea\classes\IDigitalAuthorizationCode;
use Fiea\classes\IDigitalAccessToken;
use Fiea\interfaces\IIDigitalSession;
use Fiea\classes\IDigitalDiscovery;
use Fiea\classes\IDigitalException;
use Fiea\classes\IDigitalImplicit;
use Fiea\classes\IDigitalIDToken;
use Fiea\classes\IDigitalOptions;
use Fiea\classes\IDigitalHelp;
use Fiea\classes\IDigitalHttp;
use Exception;
use stdClass;

class IDigital {
    public IDigitalDiscovery $discovery;
    public IDigitalOptions $options;
    public object $jwks;

    private function __construct(IDigitalOptions $options) {
        $this->options = $options;
    }

    /**
     * @throws IDigitalException
     */
    public static function create(IDigitalOptions $options): IDigital {
        $instance = new IDigital($options);
		$instance->prepare();
		return $instance;
	}

    public function getImplicitFlow(): IDigitalImplicit {
        return new IDigitalImplicit($this);
    }

    public function getAuthorizationCodeFlow(): IDigitalAuthorizationCode {
        return new IDigitalAuthorizationCode($this);
    }

    public function isAuthenticated(array $configs, ?IIDigitalSession $session = null): object {
        $IDigitalSession = $this->getSession($session);
        $object = new stdClass();

        try {
            $nonce = $IDigitalSession->get('nonce');
            $idToken = $IDigitalSession->get('idToken');
            $accessToken = $IDigitalSession->get('accessToken');

            $object->idToken = IDigitalIDToken::verify($idToken, $nonce, $this->jwks, $configs);
            $object->accessToken = IDigitalAccessToken::verify($accessToken, $this->jwks, $configs);
            $object->status = true;
        } catch (Exception $e) {
            $object->status = false;
            $object->idToken = null;
            $object->accessToken = null;
        }

        return $object;
    }

    /**
     * @throws IDigitalException
     */
    public function logout(array $configs, ?IIDigitalSession $session = null, ?callable $afterSessionDestroyFn = null): string {
        $IDigitalSession = $this->getSession($session);
        $url = $configs['postLogoutRedirectUri'];

        if ($this->isAuthenticated($configs, $IDigitalSession)->status) {
            $endSessionEndpoint = $this->discovery->end_session_endpoint;
            $url = IDigitalHelp::getParameterizedUrl($endSessionEndpoint, [
                ['post_logout_redirect_uri', $configs['postLogoutRedirectUri']],
                ['client_id', $configs['clientId']]
            ]);

            // Destroy IDigital object
            $IDigitalSession->flush();
        }

        // Run function after session destroy
        if (is_callable($afterSessionDestroyFn)) {
            $afterSessionDestroyFn();
        }

        return $url;
    }

    public function getSession(?IIDigitalSession $local): IIDigitalSession {
        return $local ?? $this->options->getSession();
    }

    /**
     * @throws IDigitalException
     */
    private function prepare(): void {
        $this->discovery = $this->getDiscovery();
        $this->jwks = $this->getJwks();
    }

    /**
     * @throws IDigitalException
     */
    private function getDiscovery(): IDigitalDiscovery {
        $issuer = $this->options->issuer;
        $pathname = IDigitalDiscovery::$PATHNAME;
        $url = join('/', [$issuer, $pathname]);
        return IDigitalHttp::getDiscovery($url);
    }

    /**
     * @throws IDigitalException
     */
    private function getJwks(): object {
        $url = $this->discovery->jwks_uri;
        return IDigitalHttp::getJwks($url);
    }
}