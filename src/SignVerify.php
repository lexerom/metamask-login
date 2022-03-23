<?php

namespace lexerom;

use Elliptic\EC;
use Exception;
use kornrunner\Keccak;

class SignVerify
{
    const SHA3_NULL_HASH = 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470';

    /**
     * @var EC
     */
    private $secp256k1;

    public function __construct()
    {
        $this->secp256k1 = new EC('secp256k1');
    }

    /**
     * @param string $msg
     * @param string $sign
     * @param string $address
     * @return bool
     * @throws Exception
     */
    public function verify(string $msg, string $sign, string $address): bool
    {
        if (strlen($sign) !== 132) {
            throw new \InvalidArgumentException('Invalid signature length');
        }

        $r = substr($sign, 2, 64);
        $s = substr($sign, 66, 64);
        $v = ord(hex2bin(substr($sign, 130, 2))) - 27;

        if ($v != ($v & 1)) {
            throw new \InvalidArgumentException('Invalid signature');
        }

        $hash = $this->hashPersonalMessage($msg);

        $publicKey = $this->secp256k1->recoverPubKey($hash, [
            'r' => $r,
            's' => $s
        ], $v);
        $publicKey = $publicKey->encode('hex');
        $publicAddress = $this->publicKeyToAddress($publicKey);
        $address = strtolower($address);
        $publicAddress = strtolower($publicAddress);

        return $publicAddress == $address;
    }

    /**
     * @param string $hash
     * @param string $r
     * @param string $s
     * @param int $v
     * @return string
     * @throws Exception
     */
    private function recoverPublicKey(string $hash, string $r, string $s, int $v): string
    {
        if (!$this->isHex($hash)) {
            throw new \InvalidArgumentException('Invalid hash format.');
        }
        $hash = $this->stripZero($hash);

        if (!$this->isHex($r) || !$this->isHex($s)) {
            throw new \InvalidArgumentException('Invalid signature format.');
        }

        $r = $this->stripZero($r);
        $s = $this->stripZero($s);

        if (strlen($r) !== 64 || strlen($s) !== 64) {
            throw new \InvalidArgumentException('Invalid signature length.');
        }

        $publicKey = $this->secp256k1->recoverPubKey($hash, [
            'r' => $r,
            's' => $s,
        ], $v);
        $publicKey = $publicKey->encode('hex');

        return '0x' . $publicKey;
    }

    /**
     * Algo: keccak256
     *
     * @param string $value
     * @return string
     * @throws Exception
     */
    private function sha3(string $value)
    {
        $hash = Keccak::hash($value, 256);

        return $hash === self::SHA3_NULL_HASH ? null : $hash;
    }

    /**
     * @param string $value
     * @return string
     */
    private function stripZero(string $value): string
    {
        return preg_replace('/^0x/', '', $value);
    }

    /**
     * @param string $value
     * @return bool
     */
    private function isHex(string $value): bool
    {
        return preg_match('/^(0x)?[a-fA-F0-9]+$/', $value) === 1;
    }

    /**
     * @param string $publicKey
     * @return string
     * @throws Exception
     */
    private function publicKeyToAddress(string $publicKey): string
    {
        if (!$this->isHex($publicKey)) {
            throw new \InvalidArgumentException('Invalid public key format.');
        }

        $publicKey = $this->stripZero($publicKey);

        if (strlen($publicKey) !== 130) {
            throw new \InvalidArgumentException('Invalid public key length.');
        }

        return '0x' . substr($this->sha3(substr(hex2bin($publicKey), 1)), 24);
    }

    /**
     * @param string $privateKey
     * @return string
     */
    private function privateKeyToPublicKey(string $privateKey): string
    {
        if (!$this->isHex($privateKey)) {
            throw new \InvalidArgumentException('Invalid private key format.');
        }
        $privateKey = $this->stripZero($privateKey);

        if (strlen($privateKey) !== 64) {
            throw new \InvalidArgumentException('Invalid private key length.');
        }
        $privateKey = $this->secp256k1->keyFromPrivate($privateKey, 'hex');
        $publicKey = $privateKey->getPublic(false, 'hex');

        return '0x' . $publicKey;
    }

    /**
     * @param string $message
     * @return string
     * @throws Exception
     */
    private function hashPersonalMessage(string $message): string
    {
        $prefix = sprintf("\x19Ethereum Signed Message:\n%d", mb_strlen($message));

        return $this->sha3($prefix . $message);
    }
}
