<?php

namespace RotealaBlockchain\models;
enum TransactionStatus: string
{
    case PENDING = '001';
    case VALIDATED = '002';
    case PROCESSED = '003';
    case SUCCESS = '004';

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
