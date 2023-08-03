<?php

namespace RotealaBlockchain\models;
enum TransactionStatus: int
{
    case PENDING = 1;
    case VALIDATED = 2;
    case PROCESSED = 3;
    case SUCCESS = 4;

    public function getCode(): string
    {
        return $this->value;
    }

    public static function valueOfCode(string $code): ?String
    {
        foreach (self::cases() as $case) {
            if ($case->getCode() === $code) {
                return $case->name;
            }
        }

        return null;
    }
}
