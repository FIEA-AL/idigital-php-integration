<?php

namespace Fiea\classes;
use Exception;

class IDigitalHttp {
    private static string $WWW_FORM_TYPE = 'application/x-www-form-urlencoded';
    private static string $JSON_TYPE = 'application/json';

    /**
     * @throws IDigitalException
     */
    public static function getDiscovery(string $url): IDigitalDiscovery {
        return new IDigitalDiscovery(self::get($url));
    }

    /**
     * @throws IDigitalException
     */
    public static function getJwks(string $url): object {
        return self::get($url);
    }

    /**
     * @throws IDigitalException
     */
    public static function getTokens(string $url, $body): object {
        return self::post($url, $body);
    }

    /**
     * @throws IDigitalException
     */
    private static function get(string $url): object {
        try {
            $curl = curl_init();

            $options = [
                CURLOPT_URL =>  $url,
                CURLOPT_SSL_VERIFYHOST => 0,
                CURLOPT_SSL_VERIFYPEER => 0,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
                CURLOPT_HTTPHEADER => ["Content-Type: " . self::$JSON_TYPE]
            ];

            curl_setopt_array($curl, $options);
            $response = curl_exec($curl);
            curl_close($curl);

            return json_decode($response);
        } catch (Exception $e) {
            $message = IDigitalMessage::$HTTP_ERROR;
            throw new IDigitalException(500, $message);
        }
    }

    /**
     * @throws IDigitalException
     */
    private static function post(string $url, $body): object {
        try {
            $curl = curl_init();

            $options = [
                CURLOPT_POST => 1,
                CURLOPT_URL =>  $url,
                CURLOPT_SSL_VERIFYHOST => 0,
                CURLOPT_SSL_VERIFYPEER => 0,
                CURLOPT_POSTFIELDS => $body,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
                CURLOPT_HTTPHEADER => ["Content-Type: " . self::$WWW_FORM_TYPE]
            ];

            curl_setopt_array($curl, $options);
            $response = curl_exec($curl);
            curl_close($curl);

            return json_decode($response);
        } catch (Exception $e) {
            $message = IDigitalMessage::$HTTP_ERROR;
            throw new IDigitalException(500, $message);
        }
    }
}