<?php

namespace RotealaBlockchain\models;

use BitcoinPHP\BitcoinECDSA\BitcoinECDSA;

use Brick\Math\BigInteger;
use Brick\Math\Exception\MathException;
use ECDSA\Algorithms;
use ECDSA\curves\Curves;
use ECDSA\Key;
use ECDSA\Math;

/**
 * Wraps the Key class and extends to accommodate address generation methods
*/
class ECKeyWrapper extends Key
{
    //
    public function __construct(Curves $curve, Algorithms $algorithm,  Key $key = null)
    {
        parent::__construct($curve, $algorithm);

        if($key == null) {
            parent::generateRandomKey();
        } else {
            parent::setPrivateKey($key->getPrivateKey());
            parent::setPublicKey($key->getPublicKey());
        }
    }

    /**
     * @throws MathException
     */
    public function toAddress() : String {
        $publicKey = parent::getPublicKey();

        $hexX = gmp_strval(gmp_init($publicKey->getX()), 16);
        $hexY = gmp_strval(gmp_init($publicKey->getY()), 16);


        $concatenatedString = $hexX.$hexY;

        $binaryKey = Math::unhexlify($concatenatedString);

        $uncompressedKey = chr(0x04).$binaryKey;

        $hash = hash(parent::getAlgorithm()->getHash(), $uncompressedKey, true);

        $ripeMDHash = hash('ripemd160', $hash, true);

        $prefixedHash = chr(0x00) . $ripeMDHash;

        $sha256Checksum = hash(parent::getAlgorithm()->getHash(),
            hash(parent::getAlgorithm()->getHash(), $prefixedHash, true), true);

        $checkSum = substr($sha256Checksum, 0, 4);

        $addressBytes = $prefixedHash . $checkSum;

        $bitcoinECDSA = new BitcoinECDSA();

        return $bitcoinECDSA->base58_encode(bin2hex($addressBytes));
    }

    //public function toWIF() : String {}

    public function getSecret() : String {
        return Math::hexlify(gmp_export(parent::getPrivateKey()->getSecret()));
    }

    public function toWIF() : String {
        $privateKey = $this->getSecret();

        $extendedKey = "80".$privateKey;

        $hash = hash(parent::getAlgorithm()->getHash(),
            hash(parent::getAlgorithm()->getHash(), $extendedKey));

        $checkSum = substr($hash, 0, 4);

        $extendedKeyWithCheckSum = $extendedKey.Math::hexlify($checkSum);

        $bitcoinECDSA = new BitcoinECDSA();
        $bitcoinECDSA->setPrivateKey($privateKey);

        //return $extendedKeyWithCheckSum;

        //return bin2hex(hash('sha256', $extendedKey, true));

        return $bitcoinECDSA->getWif(false);
    }
}