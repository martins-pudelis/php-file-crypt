<?php

require 'FileCrypt.php';

$options = array(
    'salt' => '@#@$#@RSDFSDF%$W%$TER^%YUTRYUUUUUUUUUUUU^&RTRTgfdgfdfgdfg^',
    'cryptFilterName' => 'mcrypt.rijndael-256',
    'decryptFilterName' => 'mdecrypt.rijndael-256',
    'password' => ''
);

$src = __DIR__ . '/test/files/test.txt';
$targetEncrypted = __DIR__ . '/test/files/tmp/test.crypt';
$targetDecrypted = __DIR__ . '/test/files/tmp/test.txt';

$crypt = new FileCrypt($options);
$crypt
    ->setSourceFilePath($src)
    ->setTargetFilePath($targetEncrypted)
    ->encryptFile();

$crypt->setSourceFilePath($targetEncrypted)
    ->setTargetFilePath($targetDecrypted)
    ->decryptFile();

$sourceChecksum = md5_file($src);
$targetEncryptedChecksum = md5_file($targetEncrypted);
$targetDecryptedChecksum = md5_file($targetDecrypted);

if ($sourceChecksum == $targetDecryptedChecksum) {
    echo 'Checksum matched';
} else {
    echo 'Something went wrong, files checksum\'s differs';
}