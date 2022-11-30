<?php

namespace Fiea;
use Fiea\classes\IDigitalAccessToken;
use Fiea\classes\IDigitalDiscovery;
use Fiea\classes\IDigitalException;
use Fiea\classes\IDigitalIDToken;
use Fiea\classes\IDigitalMessage;
use Fiea\classes\IDigitalSession;
use Fiea\classes\IDigitalConfig;
use Fiea\classes\IDigitalHelp;
use Fiea\classes\IDigitalHttp;
use Exception;
use stdClass;

class IDigital {
    private IDigitalDiscovery $discovery;
    private IDigitalConfig $configs;
	private object $jwks;

    private function __construct(IDigitalConfig $configs) {
        $this->configs = $configs;
    }

    public static function create(IDigitalConfig $configs): IDigital {
        $instance = new IDigital($configs);
		$instance->prepare();
		return $instance;
	}

    /**
     * @throws Exception
     */
    public function authorize(): void {
        $authorizationEndpoint = $this->discovery->authorization_endpoint;
        $pkceKeysPair = IDigitalHelp::getPkceKeysPair();
        $nonce = IDigitalHelp::getRandomBytes();
        $state = IDigitalHelp::getRandomBytes();

        // Update session object with provider response
        IDigitalSession::set('codeChallenge', $pkceKeysPair->codeChallenge);
        IDigitalSession::set('codeVerifier', $pkceKeysPair->codeVerifier);
        IDigitalSession::set('nonce', $nonce);
        IDigitalSession::set('state', $state);

        $url = IDigitalHelp::getParameterizedUrl($authorizationEndpoint, [
            ['code_challenge_method', $this->configs->codeChallengeMethod],
            ['scope', join('+', $this->configs->scopes)],
            ['code_challenge', $pkceKeysPair->codeChallenge],
            ['response_type', $this->configs->responseType],
            ['redirect_uri', $this->configs->redirectUri],
            ['resource', $this->configs->applicationHost],
            ['client_id', $this->configs->clientId],
            ['nonce', $nonce],
            ['state', $state]
        ]);

        header("Location: $url");
        exit;
    }

    /**
     * @throws IDigitalException
     */
    public function callback(string $code, string $issuer, string $state): object {
        if ($issuer !== $this->configs->issuer) {
            $message = IDigitalMessage::$DIVERGENT_ISSUER;
            throw new IDigitalException(400, $message);
        }

        if ($state !== IDigitalSession::get('state')) {
            $message = IDigitalMessage::$DIVERGENT_STATE;
            throw new IDigitalException(400, $message);
        }

        $object = new stdClass();
        $tokens = $this->getTokens($code);
        $nonce = IDigitalSession::get('nonce');
        $object->idToken = IDigitalIDToken::verify($tokens->id_token, $nonce, $this->jwks, $this->configs);
        $object->accessToken = IDigitalAccessToken::verify($tokens->access_token, $this->jwks, $this->configs);

        // Update session object with provider response
        IDigitalSession::set('accessToken', $tokens->access_token);
        IDigitalSession::set('idToken', $tokens->id_token);
        IDigitalSession::set('code', $code);
        return $object;
    }

    public function isAuthenticated(): object {
        $object = new stdClass();

        try {
            $nonce = IDigitalSession::get('nonce');
            $idToken = IDigitalSession::get('idToken');
            $accessToken = IDigitalSession::get('accessToken');

            $object->idToken = IDigitalIDToken::verify($idToken, $nonce, $this->jwks, $this->configs);
            $object->accessToken = IDigitalAccessToken::verify($accessToken, $this->jwks, $this->configs);
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
    public function logout($afterSessionDestroyFn = null): void {
        if ($this->isAuthenticated()->status) {
            $endSessionEndpoint = $this->discovery->end_session_endpoint;
            $url = IDigitalHelp::getParameterizedUrl($endSessionEndpoint, [
                ['post_logout_redirect_uri', $this->configs->postLogoutRedirectUri],
                ['client_id', $this->configs->clientId]
            ]);

            // Destroy IDigital object
            IDigitalSession::destroy();

            // Run function after session destroy
            if (is_callable($afterSessionDestroyFn)) {
                $afterSessionDestroyFn();
            }

            header("Location: $url");
            exit;
        }

        $message = IDigitalMessage::$REQUIRED_USER_FOR_LOGOUT;
        throw new IDigitalException(500, $message);
    }

    private function getTokens(string $code): object {
        $tokenEndpoint = $this->discovery->token_endpoint;
        $body = IDigitalHelp::getParameterizedUrl($tokenEndpoint, [
            ['code_challenge_method', $this->configs->codeChallengeMethod],
            ['code_challenge', IDigitalSession::get('codeChallenge')],
            ['code_verifier', IDigitalSession::get('codeVerifier')],
            ['redirect_uri', $this->configs->redirectUri],
            ['resource', $this->configs->applicationHost],
            ['grant_type', $this->configs->grantType],
            ['nonce', IDigitalSession::get('nonce')],
            ['client_id', $this->configs->clientId],
            ['code', $code]
        ]);

        return IDigitalHttp::getTokens($tokenEndpoint, $body);
    }

    private function prepare(): void {
        $this->discovery = $this->getDiscovery();
        $this->jwks = $this->getJwks();
        IDigitalSession::start();
    }

    private function getDiscovery(): IDigitalDiscovery {
        $issuer = $this->configs->issuer;
        $pathname = IDigitalDiscovery::$PATHNAME;
        $url = join('/', [$issuer, $pathname]);
        return IDigitalHttp::getDiscovery($url);
    }

    private function getJwks(): object {
        $url = $this->discovery->jwks_uri;
        return IDigitalHttp::getJwks($url);
    }
};