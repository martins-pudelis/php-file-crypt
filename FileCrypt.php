<?php

/**
 * Class FileCrypt
 */
class FileCrypt
{
    /**
     * @var null
     */
    protected $salt = null;

    /**
     * @var string
     */
    protected $cryptFilterName = 'mcrypt.rijndael-256';

    /**
     * @var null
     */
    protected $decryptFilterName = 'mdecrypt.rijndael-256';

    /**
     * @var null
     */
    protected $password = null;

    /**
     * @var null
     */
    protected $sourceFilePath = null;

    /**
     * @var null
     */
    protected $targetFilePath = null;

    /**
     * @param array $options
     * @throws Exception
     */
    public function __construct(array $options)
    {
        foreach ($options as $key => $value) {
            if (property_exists('FileCrypt', $key)) {
                $method = sprintf('set%s', ucfirst($key));
                $this->{$method}($value);
            } else {
                throw new Exception(sprintf('Invalid class property %s', $key));
            }
        }

        clearstatcache();
    }

    /**
     *
     * @throws Exception
     */
    public function encryptFile()
    {
        $targetFilePath = $this->getTargetFilePath();
        $sourceFilePath = $this->getSourceFilePath();

        if ($targetFilePath == $sourceFilePath) {
            throw new Exception('Source and target file locations should be different');
        }

        $handle = fopen($sourceFilePath, 'rb');
        $fp = fopen($targetFilePath, 'wb');

        stream_filter_append($fp, $this->getCryptFilterName(), STREAM_FILTER_WRITE, $this->getStreamOptions());

        if ($handle) {
            while (!feof($handle)) {
                $contents = fread($handle, 8192);
                fwrite($fp, $contents);
            }
        }

        fclose($handle);
        fclose($fp);
    }


    /**
     * @throws Exception
     */
    public function decryptFile()
    {
        $targetFilePath = $this->getTargetFilePath();
        $sourceFilePath = $this->getSourceFilePath();

        if ($targetFilePath == $sourceFilePath) {
            throw new Exception('Source and target file locations should be different');
        }

        $fr = fopen($sourceFilePath, 'rb');
        $fp = fopen($targetFilePath, 'wb');

        stream_filter_append($fr, $this->getDecryptFilterName(), STREAM_FILTER_READ, $this->getStreamOptions());

        if ($fr) {
            while (!feof($fr)) {
                $contents = fread($fr, 8192);

                if (feof($fr)) {

                    //Removes last \0\0\0\0\0 to get the same checksum
                    $len = strlen($contents);
                    $contents = substr($contents, 0, ($len - 5));
                }

                fwrite($fp, $contents);
            }
        }

        fclose($fr);
        fclose($fp);
    }

    /**
     * @return array
     */
    protected function getStreamOptions()
    {
        $salt = $this->getSalt();
        $password = $this->getPassword();

        $iv = substr(md5($salt, true) . md5($salt, true), 0, 8);
        $key = substr(md5($salt, true) . ($password ? md5($password, true) : '') . md5($salt, true), 0, 24);

        return array('iv' => $iv, 'key' => $key);
    }

    /**
     * @param $password
     * @return $this
     */
    public function setPassword($password)
    {
        $this->password = $password;
        return $this;
    }

    /**
     * @return null
     */
    public function getPassword()
    {
        return $this->password;
    }


    /**
     * @param $salt
     * @return $this
     */
    public function setSalt($salt)
    {
        $this->salt = $salt;
        return $this;
    }


    /**
     * @return null
     */
    public function getSalt()
    {
        return $this->salt;
    }


    /**
     * @param $sourceFilePath
     * @return $this
     * @throws Exception
     */
    public function setSourceFilePath($sourceFilePath)
    {
        if (!file_exists($sourceFilePath) || !is_file($sourceFilePath)) {
            throw new Exception(sprintf('Source file %s is missing', $sourceFilePath));
        }

        if (!is_readable($sourceFilePath)) {
            throw new Exception(sprintf('Permission denied for file %s', $sourceFilePath));
        }

        $this->sourceFilePath = $sourceFilePath;

        return $this;
    }

    /**
     * @return null
     */
    public function getSourceFilePath()
    {
        return $this->sourceFilePath;
    }


    /**
     * @param $targetFilePath
     * @return $this
     */
    public function setTargetFilePath($targetFilePath)
    {
        $this->targetFilePath = $targetFilePath;

        return $this;
    }

    /**
     * @return null
     */
    public function getTargetFilePath()
    {
        return $this->targetFilePath;
    }

    /**
     * @param string $cryptFilterName
     */
    public function setCryptFilterName($cryptFilterName)
    {
        $this->cryptFilterName = $cryptFilterName;
    }

    /**
     * @return string
     */
    public function getCryptFilterName()
    {
        return $this->cryptFilterName;
    }

    /**
     * @param $decryptFilterName
     * @return $this
     */
    public function setDecryptFilterName($decryptFilterName)
    {
        $this->decryptFilterName = $decryptFilterName;
        return $this;
    }

    /**
     * @return null
     */
    public function getDecryptFilterName()
    {
        return $this->decryptFilterName;
    }
}