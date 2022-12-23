<?php

namespace Fiea\classes;
use Fiea\interfaces\IIDigitalSession;

class IDigitalSession implements IIDigitalSession {
    private string $NAME = 'idigital';

    public function start(): void {
        if (!$this->alreadyExists()) {
            if(!isset($_SESSION)) session_start();
            $_SESSION[$this->NAME] = [];
        }
    }

    public function flush(): void {
        if ($this->alreadyExists()) {
            unset($_SESSION[$this->NAME]);
        }
    }

    public function alreadyExists(): bool {
        return isset($_SESSION) && isset($_SESSION[$this->NAME]);
    }

    public function get(string $key, $default = null) {
        if (!$this->alreadyExists()) $this->start();
        $value = $_SESSION[$this->NAME][$key];
        return $value ?? (is_callable($default) ? $default() : $default ?? null);
    }

    public function del(string $key): void {
        if (!$this->alreadyExists()) $this->start();
        unset($_SESSION[$this->NAME][$key]);
    }

    public function put(string $key, $value) {
        if (!$this->alreadyExists()) $this->start();
        $_SESSION[$this->NAME][$key] = $value;
        return $value;
    }

    public function pull(string $key, $default = null) {
        if (!$this->alreadyExists()) $this->start();
        $value = $this->get($key, $default);
        $this->del($key);
        return $value;
    }
}