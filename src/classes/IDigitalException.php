<?php

namespace Fiea\classes;
use DateTimeImmutable;
use Exception;
use Throwable;

class IDigitalException extends Exception {
    protected string $date;
    protected string $name;
    protected $message;
    protected $code;

    public function __construct($code, $message, Throwable $previous = null) {
        //  Require an array of HTTP status code
        $HTTP_STATUS = require_once(__DIR__.'/../utils/http.status.php');

        $format = 'd/m/Y H:i:s';
        $date = new DateTimeImmutable();
        $this->name = $HTTP_STATUS[$code];
        $this->date = $date->format($format);
        parent::__construct($message, $code, $previous);
    }

    public function __toString() {
        return __CLASS__ . ": [$this->date: $this->code - $this->name]: $this->message\n";
    }
}