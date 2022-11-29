<?php

namespace Fiea\classes;

class IDigitalHttp {
    public static function getDiscovery(string $url): IDigitalDiscovery {
        $curl = curl_init();

        curl_setopt_array($curl, [
            CURLOPT_URL =>  $url,
            CURLOPT_SSL_VERIFYHOST => 0,
            CURLOPT_SSL_VERIFYPEER => 0,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_HTTPHEADER => ['Content-Type: application/json']
        ]);

        $response = curl_exec($curl);
        curl_close($curl);

        $json = json_decode($response);
        return new IDigitalDiscovery($json);
    }

    public static function getJwks(string $url): object {
        $curl = curl_init();

        curl_setopt_array($curl, [
            CURLOPT_URL =>  $url,
            CURLOPT_SSL_VERIFYHOST => 0,
            CURLOPT_SSL_VERIFYPEER => 0,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_HTTPHEADER => ['Content-Type: application/json']
        ]);

        $response = curl_exec($curl);
        curl_close($curl);

        return json_decode($response);
    }

    public static function getTokens(string $url, $body) {
        $curl = curl_init();

        curl_setopt_array($curl, [
            CURLOPT_POST => 1,
            CURLOPT_URL =>  $url,
            CURLOPT_POSTFIELDS => $body,
            CURLOPT_SSL_VERIFYHOST => 0,
            CURLOPT_SSL_VERIFYPEER => 0,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_HTTPHEADER => ['Content-Type: application/x-www-form-urlencoded']
        ]);

        $response = curl_exec($curl);
        curl_close($curl);

        return json_decode($response);
    }
}