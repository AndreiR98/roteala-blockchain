<?php

use ECDSA\Algorithms;
use ECDSA\curves\Curves;
use ECDSA\Key;
use RotealaBlockchain\Blockchain;
use RotealaBlockchain\models\ECKeyWrapper;
use RotealaBlockchain\models\PseudoTransaction;
use RotealaBlockchain\models\TransactionStatus;

require_once(__DIR__.'/vendor/autoload.php');
echo "<pre>";

$key = new Key(Curves::SECP256k1(), Algorithms::ES256());
$key->fromHexFormat("a2480b12b793611dcf98b16a719d828bddbc3118e7f566146e0f597783f28800");

$keyWrapper = new ECKeyWrapper(Curves::SECP256k1(), Algorithms::ES256(), $key);

$pseudoTransaction = new PseudoTransaction();
$pseudoTransaction->setFrom($keyWrapper->toAddress());
$pseudoTransaction->setTo("1JPn12zyaT339bm33X4gxd1uAmowpRqREB");
$pseudoTransaction->setNonce(1);
$pseudoTransaction->setStatus(TransactionStatus::PENDING);
$pseudoTransaction->setTimeStamp(time());
$pseudoTransaction->setVersion(0x10);
$pseudoTransaction->setValue("200");
$pseudoTransaction->signPseudoTransaction($key);

echo ($pseudoTransaction)."<br>";

//print_r(Blockchain::generateNewKey()->toAddress());