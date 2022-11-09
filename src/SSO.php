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
     * Cria a instância da classe e busca no Well Known as configurações
     * @param string $provider
     * @param string $redirect_uri
     * @param string $client_id
     * @param string $logout_redirect_uri
     */
    public function __construct($provider, $redirect_uri, $client_id, $logout_redirect_uri)
    {
        $this->provider = $provider;
        $this->redirect_uri = $redirect_uri;
        $this->client_id = $client_id;
        $this->logout_redirect_uri = $logout_redirect_uri;
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
     * @return string
     */
    public function generateRedirect()
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
        $url .= 'scope=' . 'profile+openid' . '&';
        $url .= 'code_challenge_method=S256&';
        $url .= 'code_challenge=' . $code_challenge;
        //$url .= 'code_verifier=' . $code_verifier;

        $_SESSION['code_verifier'] = $code_verifier;
        $_SESSION['code_challenge'] = $code_challenge;
        $_SESSION['state'] = $state;
        $_SESSION['nonce'] = $nonce;
        
        return $url;
    }

    /**
     * Busca o id_token na seção e válida o mesmo usando as chaves JWKs que vem do .well-known
     * @return object|null
     */
    public function checkToken()
    {
        $id_token = $_SESSION['id_token'];
        if (!$id_token) return null;

        try {
            $seperate_token = explode('.', $id_token);
            if (count($seperate_token) <= 0) {
                return null;
            }
            $header = base64_decode($seperate_token[0]);
            $header = json_decode($header, true);

            $alg = $header['alg'] ?? 'RS256';
            $kid = $header['kid'] ?? "";
            if (!$kid) {
                return null;
            }

            $public_key = null;
            foreach ($this->keys as $value) {
                if ($value['kid'] == $kid && $value['alg'] == $alg) {
                    $public_key = $value;
                }
            }

            $jwk = JWK::parseKey($public_key);
            $payload = JWT::decode($id_token, $jwk);

            return $payload;
        } catch (Exception $e) {
            return null;
        }
    }

    /**
     * Realiza um POST request no SSO para buscar os tokens do usuário, usando o CODE
     * @param string $code
     * @return array
     */
    public function signInWithCode($code)
    {
        $code_verifier = $_SESSION['code_verifier'];
        $code_challenge = $_SESSION['code_challenge'];

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
        if(isset($result['access_token'])){
            $_SESSION['access_token'] = $result['access_token'];
        }
        if(isset($result['expires_in'])){
            $_SESSION['expires_in'] = $result['expires_in'];
        }
        if(isset($result['token_type'])){
            $_SESSION['token_type'] = $result['token_type'];
        }
        if(isset($result['id_token'])){
            $_SESSION['id_token'] = $result['id_token'];
            $payload = $this->checkToken();
            if (!isset($payload)) {
                $this->logout();
                return ['success' => false, 'result' => 'Token inválido'];
            }
            if ($payload->sub ?? "") {
                $_SESSION['nome'] = $payload->displayName ?? "";
                $_SESSION['user_id'] = $payload->sub ?? "";
                $this->getProfile();
            }
        }
        return ['success' => true, 'result' => true];
    }

    public function getProfile()
    {
        
        $user_id = $_SESSION['user_id'];
        $access_token = $_SESSION['access_token'];

        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $this->provider . '/user/' . $user_id,
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/json',
                'Authorization: Bearer '.$access_token
            ],
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_SSL_VERIFYHOST => 0,
            CURLOPT_SSL_VERIFYPEER => 0,
        ]);
        $response = curl_exec($ch);
        curl_close($ch);
        $result = json_decode($response, true);

        $user = $result['data']['items'][0];
        $emails = [];
        foreach ($user['emails'] as $email) {
            $emails[] = [
                'id'    => $email['id'],
                'type'  => $email['type'],
                'value' => $email['value']
            ];
        }

        if (isset($user['displayame'])) {
            $_SESSION['nome'] = $user['name']['displayname'];
        }
        if (isset($user['picture'])) {
            $_SESSION['picture'] = $user['picture'];
        }
        if (count($emails) > 0) {
            $_SESSION['email'] = $emails[0]['value'];
        }
        
        return ['success' => true, 'result' => $user];
    }

    /**
     * Faz a limpeza da sessão e retornar a URL para logout do SSO
     * @return string
     */
    public function logout()
    {        
        unset($_SESSION['access_token']);
        unset($_SESSION['expires_in']);
        unset($_SESSION['id_token']);
        unset($_SESSION['token_type']);
        unset($_SESSION['code_verifier']);
        unset($_SESSION['code_challenge']);
        unset($_SESSION['state']);
        unset($_SESSION['nonce']);
        unset($_SESSION['firstname']);
        unset($_SESSION['lastname']);
        unset($_SESSION['displayname']);
        unset($_SESSION['picture']);
        unset($_SESSION['user_id']);

        $url = $this->provider . '/sso/oidc/session/end?';
        $url .= 'post_logout_redirect_uri=' . $this->logout_redirect_uri . '&';
        $url .= 'client_id=' . $this->client_id;

        return $url;
    }
}
