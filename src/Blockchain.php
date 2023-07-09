<?php

namespace RotealaBlockchain;

use ECDSA\Algorithms;
use ECDSA\curves\Curves;
use ECDSA\Key;
use ECDSA\keys\PrivateKey;
use RotealaBlockchain\models\ECKeyWrapper;

class Blockchain
{
    public static function generateNewKey() : ECKeyWrapper {
        return new ECKeyWrapper(Curves::SECP256k1(), Algorithms::ES256());
    }

    public static function convertKeyToAddress(Key $key) : ECKeyWrapper {
        return new ECKeyWrapper(Curves::SECP256k1(), Algorithms::ES256(), $key);
    }

}