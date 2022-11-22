<?php

namespace Fiea;

use Fiea\Exceptions\InvalidWellKnownException;
use Exception;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;

class SSO
{
    /**
     * URL do provedor
     * @var string
     */
    private $provider;
    /**
     * URL para fazer o redirect após o login no SSO
     * @var string
     */
    private $redirect_uri;
    /**
     * URL para fazer o redirect após o logout no SSO
     * @var string
     */
    private $logout_redirect_uri;
    /**
     * CLIENT ID no SSO
     */
    private $client_id;
    /**
     * Resource
     */
    private $resource;
    /**
     * Caminho para realizar o redirect
     * @var string
     */
    private $authorization_endpoint = "";
    /**
     * URL para buscar os JWKS
     * @var string
     */
    private $jwks_uri = "";
    /**
     * JWKS encontradas
     * @var array
     */
    private $keys = [];
    /**
     * Verifica se usa o Backchannel
     * @var bool 
     */
    private $use_backchannel = false;
    
    /**
     * Cria a instância da classe e busca no Well Known as configurações
     * @param string $provider
     * @param string $redirect_uri
     * @param string $client_id
     * @param string $logout_redirect_uri
     * @param string $resource
     * @param bool   $use_backchannel
     */
    public function __construct($provider, $redirect_uri, $client_id, $logout_redirect_uri, $resource, $use_backchannel = false)
    {
        $this->provider = $provider;
        $this->redirect_uri = $redirect_uri;
        $this->client_id = $client_id;
        $this->logout_redirect_uri = $logout_redirect_uri;
        $this->resource = $resource;
        $this->use_backchannel = $use_backchannel;
        $this->getWellKnown();
    }

    /**
     * Consultando o wellKnown para usar algumas configurações
     */
    public function getWellKnown()
    {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL =>  $this->provider . '/sso/oidc/.well-known/openid-configuration',
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/json',
            ],
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_SSL_VERIFYHOST => 0,
            CURLOPT_SSL_VERIFYPEER => 0,
        ]);
        $response = curl_exec($ch);
        curl_close($ch);

        $result = json_decode($response, true);

        if(!isset($result['authorization_endpoint']))
        {
            throw new InvalidWellKnownException('authorization_endpoint não foi encontrado'); 
        }
        $this->authorization_endpoint = $result['authorization_endpoint'];
        if(!isset($result['jwks_uri']))
        {
            throw new InvalidWellKnownException('jwks_uri não foi encontrado'); 
        }
        $this->jwks_uri = $result['jwks_uri'];
        $this->getJwks();
    }

    /**
     * Buscando chaves no SSO do JWKs
     */
    public function getJwks()
    {
       $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $this->jwks_uri,
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/json',
            ],
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_SSL_VERIFYHOST => 0,
            CURLOPT_SSL_VERIFYPEER => 0,
        ]);
        $response = curl_exec($ch);
        curl_close($ch);
        $result = json_decode($response, true);
        $this->keys = isset($result['keys'][0]) ? $result['keys'] : [];
    }

    /**
     * Gera a URL para redirecionar a aplicação para o LOGIN no SSO
     * @param string $scope
     * @return string
     */
    public function generateRedirect($scope = 'profile+openid')
    {
        $code_verifier = bin2hex(random_bytes(64));
        $code_challenge = rtrim(strtr(base64_encode(hash('sha256', $code_verifier, true)), '+/', '-_'), '=');
        $state = bin2hex(random_bytes(16));
        $nonce = bin2hex(random_bytes(16));
        $url = $this->authorization_endpoint . '?';
        $url .= 'response_type=code&';
        $url .= 'redirect_uri=' . $this->redirect_uri . '&';
        $url .= 'client_id=' . $this->client_id . '&';
        $url .= 'nonce=' . $nonce . '&';
        $url .= 'state=' . $state . '&';
        $url .= 'scope=' . $scope . '&';
        $url .= 'code_challenge_method=S256&';
        $url .= 'code_challenge=' . $code_challenge;
        $url .= '&resource='.$this->resource;

        if(!isset($_SESSION))
        {
            session_start();
        }

        $_SESSION['code_verifier'] = $code_verifier;
        $_SESSION['code_challenge'] = $code_challenge;
        $_SESSION['state'] = $state;
        $_SESSION['nonce'] = $nonce;
        
        return $url;
    }

    /**
     * Realiza um POST request no SSO para buscar os tokens do usuário, usando o CODE
     * @param string $code
     * @return array
     */
    public function signInWithCode($code)
    {
        $code_verifier = $_SESSION['code_verifier'] ?? "";
        $code_challenge = $_SESSION['code_challenge'] ?? "";

        $body  = "grant_type=authorization_code";
        $body .= "&redirect_uri=" . $this->redirect_uri;
        $body .= "&client_id=". $this->client_id;
        $body .= "&code=". $code;
        $body .= "&code_challenge_method=S256";
        $body .= "&code_challenge=".$code_challenge;
        $body .= "&code_verifier=".$code_verifier;

        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $this->provider."/sso/oidc/token",
            CURLOPT_POST => 1,
            CURLOPT_POSTFIELDS => $body,
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/x-www-form-urlencoded',
            ],
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_SSL_VERIFYHOST => 0,
            CURLOPT_SSL_VERIFYPEER => 0,
        ]);

        $response = curl_exec($ch);
        curl_close($ch);

        $result = json_decode($response, true);
        if(!isset($result['id_token'])){
            return ['success' => false, 'result' => 'ID Token não informado'];
        }

        $sessionHelper = new SessionHelper($result['id_token'], $this->keys, $this->use_backchannel);
        $sessionHelper->set('id_token', $result['id_token']);
        $sessionHelper->set('access_token', $result['access_token']);
        $sessionHelper->set('expires_in', $result['expires_in'] ?? "");
        $sessionHelper->set('token_type', $result['token_type'] ?? '');

        $this->refreshUser($sessionHelper->payload);
       
        return ['success' => true, 'result' => true];
    }

    public function getProfile()
    {
        $session = new SessionHelper();

        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $this->provider . '/user/me',
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/json',
                'Authorization: Bearer '.$session->get('access_token')
            ],
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_SSL_VERIFYHOST => 0,
            CURLOPT_SSL_VERIFYPEER => 0,
        ]);
        $response = curl_exec($ch);
        curl_close($ch);
        $result = json_decode($response, true);

        var_dump($result);
        die();

        $user = $result['data']['items'][0];
        $emails = [];
        foreach ($user['emails'] as $email) {
            $emails[] = [
                'id'    => $email['id'],
                'type'  => $email['type'],
                'value' => $email['value']
            ];
        }
        $sessionHelper = new SessionHelper();
        if (isset($user['name']['givenName'])) {
            $sessionHelper->set('firstname', $user['name']['givenName']);
        }
        if (isset($user['name']['familyName'])) {
            $sessionHelper->set('lastname', $user['name']['familyName']);
        }
        if (isset($user['displayname'])) {
            $sessionHelper->set('displayname', $user['name']['displayname']);
        }
        if (isset($user['picture'])) {
            $sessionHelper->set('picture', $user['picture']);
        }
        if (count($emails) > 0) {
            $sessionHelper->set('email', isset($emails[0]['value']) ? $emails[0]['value'] : '');
        }

        $sessionHelper->set('groups',   $user['groups'] ?? []);
        $sessionHelper->set('services', $user['services'] ?? []);
        
        return ['success' => true, 'result' => $user];
    }

    /**
     * Atualiza um usuário usando o payload gerado
     * @param object $request
     * @return bool
     */
    public function refreshUser($payload): bool
    {
        $sessionHelper = new SessionHelper();
        $sessionHelper->set('firstname',   $payload->givenName ?? "");
        $sessionHelper->set('lastname',    $payload->familyName ?? "");
        $sessionHelper->set('displayname', $payload->displayName ?? "");
        $sessionHelper->set('user_id',     $payload->sub ?? "");
        $sessionHelper->set('email',       $payload->email ?? "");
        
        return true;
    }

    /**
     * Faz a limpeza da sessão e retornar a URL para logout do SSO
     * @param bool $clean
     * @param string $logout_token
     * @return string
     */
    public function logout($clean = false, $logout_token = "")
    {        
        if($clean)
        {
            $session = new SessionHelper($logout_token, $this->keys);
            $session->destroy();
        }

        $url = $this->provider . '/sso/oidc/session/end?';
        $url .= 'post_logout_redirect_uri=' . $this->logout_redirect_uri . '&';
        $url .= 'client_id=' . $this->client_id;

        return $url;
    }
}
