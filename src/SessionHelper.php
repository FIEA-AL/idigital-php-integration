<?php

namespace Fiea;

use Exception;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;


class SessionHelper
{
    /**
     * @var string $id_token
     */
    private $id_token;
    /**
     * @var array $keys
     */
    private $keys;
    /**
     * @var object $payload
     */
    public $payload;

    /**
     * Inicia as configurações para gerenciar a sessão do SSO
     * @param string|null $id_token
     * @param array  $keys
     * @param bool $use_backchannel
     */
    public function __construct($id_token = null, $keys = [], $use_backchannel = false)
    {
        $this->keys = $keys;
        if(isset($id_token))
        {
            $this->id_token = $id_token;
            $payload = $this->verifyToken();
            if(!isset($payload)) {
                throw new Exception('ID Token informado é inválido');
            }
            $this->payload = $payload;

            if($use_backchannel)
            {
                if(!isset($payload->sid)) {
                    throw new Exception('SID não informado');
                }
                $sid = str_replace('_', '-', $payload->sid);
                if(!isset($_SESSION)){
                    session_destroy();
                }
                session_id($sid);
            }
        }

        if(!isset($_SESSION))
        {
            session_start();
        }

        if(isset($_SESSION['id_token']) && !isset($id_token))
        {
            $this->id_token = $_SESSION['id_token'];
        }
    }

    /**
     * Verifica o token e retornar o payload caso for válido, se não retorna nulo
     * @return object|null $payload
     */
    public function verifyToken()
    {
        try {
            $seperate_token = explode('.', $this->id_token);
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
            $payload = JWT::decode($this->id_token, $jwk);

            return $payload;
        } catch (Exception $e) {
            return null;
        }
    }

    /**
     * Salva a sessão
     * @param string $key
     * @param mixed $value
     */
    public function set($key, $value)
    {
        $_SESSION[$key] = $value;
    }

    /**
     * Pegar o valor de sessão
     * @param string $key
     * @return mixed|null
     */
    public function get($key)
    {
        return $_SESSION[$key] ?? null;
    }

    /**
     * Limpa sessao
     */
    public function destroy()
    {
        session_destroy();
    }
}
