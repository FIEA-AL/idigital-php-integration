<?php

namespace Fiea\classes;
use stdClass;

class IDigitalSession {
    private static string $NAME = 'idigital';

    public static function set(string $key, $value): void {
        if (self::alreadyExists()) {
            $_SESSION[self::$NAME][$key] = $value;
        }
    }

    public static function get(string $key) {
        if (self::alreadyExists()) {
            return $_SESSION[self::$NAME][$key] ?? null;
        }
    }

    public static function alreadyExists(): bool {
        return isset($_SESSION) && isset($_SESSION[self::$NAME]);
    }

    public static function start() {
        if (!self::alreadyExists()) {
            if(!isset($_SESSION))  {
                session_start();
            }

            // IDigital session object
            $_SESSION[self::$NAME] = [];
        }
    }

    public static function destroy() {
        if (self::alreadyExists()) {
            unset($_SESSION[self::$NAME]);
        }
    }
}