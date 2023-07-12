<?php

namespace RotealaBlockchain\models;

use ECDSA\ECDSA;
use ECDSA\Key;
use ECDSA\keys\PrivateKey;
use ECDSA\Math;
use ECDSA\Signature;

class PseudoTransaction
{
    private string $pseudoHash;
    private string $from;
    private string $to;
    private int $version;
    private string $value;
    private string $fees;
    private int $nonce;
    private int $timeStamp;
    private TransactionStatus $status;
    private string $pubKeyHash;
    private Signature $signature;

    public function __construct() {}

    /**
     * @param string $pseudoHash
     */
    public function setPseudoHash(string $pseudoHash): void
    {
        $this->pseudoHash = $pseudoHash;
    }

    /**
     * @param string $from
     */
    public function setFrom(string $from): void
    {
        $this->from = $from;
    }

    /**
     * @param string $to
     */
    public function setTo(string $to): void
    {
        $this->to = $to;
    }

    /**
     * @param int $version
     */
    public function setVersion(int $version): void
    {
        $this->version = $version;
    }

    /**
     * @param string $value
     */
    public function setValue(string $value): void
    {
        $this->value = $value;
    }

    /**
     * @param int $timeStamp
     */
    public function setTimeStamp(int $timeStamp): void
    {
        $this->timeStamp = $timeStamp;
    }

    /**
     * @param TransactionStatus $status
     */
    public function setStatus(TransactionStatus $status): void
    {
        $this->status = $status;
    }

    /**
     * @param string $pubKeyHash
     */
    public function setPubKeyHash(string $pubKeyHash): void
    {
        $this->pubKeyHash = $pubKeyHash;
    }

    /**
     * @param Signature $signature
     */
    public function setSignature(Signature $signature): void
    {
        $this->signature = $signature;
    }

    /**
     * @return string
     */
    public function getFrom(): string
    {
        return $this->from;
    }

    /**
     * @return string
     */
    public function getPseudoHash(): string
    {
        return $this->pseudoHash;
    }

    /**
     * @return string
     */
    public function getFees(): string
    {
        return $this->fees;
    }

    /**
     * @param string $fees
     */
    public function setFees(string $fees): void
    {
        $this->fees = $fees;
    }

    /**
     * @return string
     */
    public function getPubKeyHash(): string
    {
        return $this->pubKeyHash;
    }

    /**
     * @return array
     */
    public function getSignature(): Array
    {
        return ["r"=>Math::hexlify(gmp_export($this->signature->getR())),
            "s"=>Math::hexlify(gmp_export($this->signature->getS()))];
    }

    /**
     * @return String
     */
    public function getStatus(): String
    {
        return $this->status->getCode();
    }

    /**
     * @return int
     */
    public function getTimeStamp(): int
    {
        return $this->timeStamp;
    }

    /**
     * @return string
     */
    public function getTo(): string
    {
        return $this->to;
    }

    /**
     * @return string
     */
    public function getValue(): string
    {
        return $this->value;
    }

    /**
     * @return int
     */
    public function getVersion(): int
    {
        return $this->version;
    }

    /**
     * @param int $nonce
     */
    public function setNonce(int $nonce): void
    {
        $this->nonce = $nonce;
    }

    /**
     * @return int
     */
    public function getNonce(): int
    {
        return $this->nonce;
    }

    /**
     * This is used when signing the transaction
    */
    private function signingData(Key $privateKey): string{
        $keyData = Math::int2hex(gmp_init($privateKey->getPublicKey()->getX())).
            Math::int2hex(gmp_init($privateKey->getPublicKey()->getY()));

        $algorithmHash = $privateKey->getAlgorithm()->getHash();

        $publicKeyHash = hash($algorithmHash, hash($algorithmHash, Math::unhexlify($keyData), true),true);

        $this->pubKeyHash = Math::hexlify($publicKeyHash);

        //Add all the fields in an array order them alphabetically
        $fields = [
            "from"=>$this->from,
            "to"=>$this->to,
            "fees"=>$this->fees,
            "version"=>$this->version,
            "value"=>$this->value,
            "timeStamp"=>$this->timeStamp,
            "pubKeyHash"=>$this->pubKeyHash,
            "nonce"=>$this->nonce
        ];

        //Order the fields
        ksort($fields);

        return json_encode($fields);
    }

    public function signPseudoTransaction(Key $privateKey): PseudoTransaction {
        //Send the transaction JSON data to ECDSA, ECDSA will handle the hashing
        $signingData = $this->signingData($privateKey);

        $signature = ECDSA::Sign($signingData, $privateKey);

        $algorithmHash = $privateKey->getAlgorithm()->getHash();

        $this->setSignature($signature);

        //Compute the pseudoHash

        $fields = [
            "from"=>$this->from,
            "to"=>$this->to,
            "fees"=>$this->fees,
            "version"=>$this->version,
            "value"=>$this->value,
            "timeStamp"=>$this->timeStamp,
            "pubKeyHash"=>$this->pubKeyHash,
            "nonce"=>$this->nonce,
            "signature"=>$this->getSignature()
        ];

        //Order the fields
        ksort($fields);

        $pseudoHash = hash($algorithmHash, json_encode($fields));

        $this->setPseudoHash($pseudoHash);

        return $this;
    }

    public function __toString() : String {
        $fields = [
            "pseudo_hash"=>$this->pseudoHash,
            "from"=>$this->from,
            "to"=>$this->to,
            "fees"=>$this->fees,
            "version"=>$this->version,
            "value"=>$this->value,
            "time_stamp"=>$this->timeStamp,
            "pub_key_hash"=>$this->pubKeyHash,
            "nonce"=>$this->nonce,
            "signature"=>$this->getSignature(),
            "status"=>$this->getStatus()];

        ksort($fields);

        return json_encode($fields);
    }
}