<?php

declare(strict_types=1);

namespace Webrtc\Srtp;

use danog\MadelineProto\Native\AesGcm;
use phpseclib4\Crypt\AES as PhpseclibAes;
use Webrtc\Srtp\Exception\SrtpException;

/**
 * An AES-GCM key, set up once for all the packets it protects (see {@see Aes} for the backends).
 *
 * It's serialized as the key alone: the backend is chosen again when it's unserialized.
 */
final class AesGcmKey
{
    /** @var Aes::BACKEND_* */
    private string $backend;
    private ?AesGcm $native = null;
    private string $opensslName = '';
    private ?PhpseclibAes $phpseclib = null;
    private ?AesCtrKey $ctr = null;

    /** @throws SrtpException If the key isn't 16, 24 or 32 bytes long. */
    public function __construct(#[\SensitiveParameter] private string $key)
    {
        $this->setUp();
    }

    private function setUp(): void
    {
        $length = \strlen($this->key);
        if ($length !== 16 && $length !== 24 && $length !== 32) {
            throw new SrtpException('Invalid AES key length!');
        }
        $this->backend = Aes::backend('gcm', $length);
        $this->native = $this->backend === Aes::BACKEND_NATIVE ? new AesGcm($this->key) : null;
        $this->opensslName = Aes::opensslName('gcm', $length);
        $this->phpseclib = null;
        $this->ctr = null;
    }

    /**
     * Encrypt, returning the ciphertext followed by the 16-byte authentication tag.
     *
     * @throws SrtpException If encryption fails.
     */
    public function encrypt(string $nonce, string $aad, string $plaintext): string
    {
        if ($this->native !== null) {
            return $this->native->encrypt($nonce, $aad, $plaintext);
        }
        switch ($this->backend) {
            case Aes::BACKEND_SODIUM:
                return sodium_crypto_aead_aes256gcm_encrypt($plaintext, $aad, $nonce, $this->key);
            case Aes::BACKEND_OPENSSL:
                $tag = '';
                $ciphertext = openssl_encrypt($plaintext, $this->opensslName, $this->key, OPENSSL_RAW_DATA, $nonce, $tag, $aad, 16);
                if ($ciphertext === false || \strlen($tag) !== 16) {
                    throw new SrtpException('AES-GCM encryption failed!');
                }
                return $ciphertext.$tag;
            default:
                $aes = $this->phpseclib ??= Aes::phpseclib('gcm', $this->key);
                $aes->setNonce($nonce);
                $aes->setAAD($aad);
                $ciphertext = $aes->encrypt($plaintext);
                return $ciphertext.$aes->getTag();
        }
    }

    /**
     * Decrypt and verify the 16-byte authentication tag (in constant time).
     *
     * @return string|false The plaintext, or false if authentication fails.
     */
    public function decrypt(string $nonce, string $aad, string $ciphertext, string $tag): string|false
    {
        if ($this->native !== null) {
            return $this->native->decrypt($nonce, $aad, $ciphertext, $tag);
        }
        switch ($this->backend) {
            case Aes::BACKEND_SODIUM:
                return sodium_crypto_aead_aes256gcm_decrypt($ciphertext.$tag, $aad, $nonce, $this->key);
            case Aes::BACKEND_OPENSSL:
                return openssl_decrypt($ciphertext, $this->opensslName, $this->key, OPENSSL_RAW_DATA, $nonce, $tag, $aad);
            default:
                // GCM with a 96-bit nonce encrypts from inc32(J0) = nonce || 2. Derive a candidate
                // plaintext without releasing it, then run the authenticated encryption direction
                // and compare its complete result in constant time. This avoids phpseclib's portable
                // GCM decrypt path, whose tag comparison is not constant-time.
                $this->ctr ??= new AesCtrKey($this->key, Aes::BACKEND_PHPSECLIB);
                $plain = $this->ctr->apply($nonce.pack('N', 2), $ciphertext);
                $verified = $this->encrypt($nonce, $aad, $plain);
                $ciphertextValid = hash_equals(substr($verified, 0, -16), $ciphertext);
                $tagValid = hash_equals(substr($verified, -16), $tag);
                return $ciphertextValid && $tagValid ? $plain : false;
        }
    }

    /** @return Aes::BACKEND_* */
    public function getBackend(): string
    {
        return $this->backend;
    }

    /** @return array{key: string} */
    public function __serialize(): array
    {
        return ['key' => $this->key];
    }

    /** @param array{key: string} $data */
    public function __unserialize(array $data): void
    {
        $this->key = $data['key'];
        $this->setUp();
    }

    public function __debugInfo(): array
    {
        return ['backend' => $this->backend];
    }
}
