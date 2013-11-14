<?php

require '../FileCrypt.php';

class FileCryptTest extends PHPUnit_Framework_TestCase
{
    /**
     * @var array
     */
    protected $options = array();

    /**
     * @var null|FileCrypt
     */
    protected $crypt = null;

    /**
     * Setup objects
     */
    public function setUp()
    {
        $this->options = array(
            'salt' => '@#@$#@RSDFSDF%$W%$TER^%YUTRYUUUUUUUUUUUU^&RTRTgfdgfdfgdfg^',
            'cryptFilterName' => 'mcrypt.rijndael-256',
            'decryptFilterName' => 'mdecrypt.rijndael-256',
            'password' => ''
        );

        $this->crypt = new FileCrypt($this->options);

    }

    public function testInvalidFile()
    {
        $src =__DIR__ . '/files/test2.txt';

        $this->setExpectedException('Exception', sprintf('Source file %s is missing', $src));

        $this->crypt->setSourceFilePath($src);
    }

    public function testInvalidProperty()
    {
        $options = array(
            'salt' => '@#@$#@RSDFSDF%$W%$TER^%YUTRYUUUUUUUUUUUU^&RTRTgfdgfdfgdfg^',
            'cryptfiltername' => 'mcrypt.rijndael-256',
            'decryptFilterName' => 'mdecrypt.rijndael-256',
            'password' => ''
        );

        $this->setExpectedException('Exception', sprintf('Invalid class property %s', 'cryptfiltername'));

        new FileCrypt($options);
    }

    public function testSourceTargetFilesSamePath()
    {
        $src = __DIR__ . '/files/test.txt';

        $this->crypt->setSourceFilePath($src);
        $this->crypt->setTargetFilePath($src);

        $this->setExpectedException('Exception', 'Source and target file locations should be different');
        $this->crypt->encryptFile();
    }

    public function testIsFileAfterwardsTheSame()
    {
        $src = __DIR__ . '/files/test.txt';
        $targetEncrypted = __DIR__ . '/files/tmp/test.crypt';
        $targetDecrypted = __DIR__ . '/files/tmp/test.txt';

        $crypt = $this->crypt;
        $crypt
            ->setSourceFilePath($src)
            ->setTargetFilePath($targetEncrypted)
            ->encryptFile();

        $crypt->setSourceFilePath($targetEncrypted)
            ->setTargetFilePath($targetDecrypted)
            ->decryptFile();

        $sourceChecksum = md5_file($src);
        $targetDecryptedChecksum = md5_file($targetDecrypted);

        $this->assertEquals($sourceChecksum, $targetDecryptedChecksum);
    }
}