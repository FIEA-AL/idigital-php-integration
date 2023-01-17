<?php

namespace Fiea\interfaces;

interface IIDigitalSession {
    public function pull(string $key, $default = null);
    public function get(string $key, $default = null);
    public function put(string $key, $value);
    public function flush();
}