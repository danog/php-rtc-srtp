<?php

declare(strict_types=1);

namespace Webrtc\Srtp;

use phpseclib4\Crypt\AES as PhpseclibAes;
use Webrtc\Srtp\Exception\SrtpException;

/**
 * The AES primitives of SRTP (GCM and CTR), using the fastest implementation available.
 *
 * libsodium is used for AES-256-GCM, if the CPU supports it; OpenSSL for everything else; phpseclib if
 * OpenSSL isn't available. Every packet is protected with a different nonce, but with the same few keys:
 * phpseclib ciphers are kept for every key, instead of being set up for every packet.
 *
 * @internal
 */
final class Aes
{
    public const BACKEND_SODIUM = 'sodium';
    public const BACKEND_OPENSSL = 'openssl';
    public const BACKEND_PHPSECLIB = 'phpseclib';

    /** How many phpseclib ciphers to keep, at most: a session uses a few keys at a time. */
    private const MAX_CACHED_CIPHERS = 64;

    /**
     * The backend to use, instead of the fastest available one (if available): for tests.
     *
     * @var self::BACKEND_*|null
     */
    public static ?string $backend = null;

    /** @var array<string, PhpseclibAes> phpseclib ciphers, by mode and key. */
    private static array $ciphers = [];

    private static ?bool $sodiumGcm = null;
    /** @var array<string, bool> Whether OpenSSL supports a cipher, by name. */
    private static array $opensslCiphers = [];

    /**
     * Encrypt with AES-GCM, returning the ciphertext followed by the 16-byte authentication tag.
     *
     * @throws SrtpException If encryption fails.
     */
    public static function gcmEncrypt(string $key, string $nonce, string $aad, string $plaintext): string
    {
        switch (self::backend('gcm', $key)) {
            case self::BACKEND_SODIUM:
                return sodium_crypto_aead_aes256gcm_encrypt($plaintext, $aad, $nonce, $key);
            case self::BACKEND_OPENSSL:
                $tag = '';
                $ciphertext = openssl_encrypt($plaintext, self::opensslName('gcm', $key), $key, OPENSSL_RAW_DATA, $nonce, $tag, $aad, 16);
                if ($ciphertext === false || \strlen($tag) !== 16) {
                    throw new SrtpException('AES-GCM encryption failed!');
                }
                return $ciphertext.$tag;
            default:
                $aes = self::cipher('gcm', $key);
                $aes->setNonce($nonce);
                $aes->setAAD($aad);
                $ciphertext = $aes->encrypt($plaintext);
                return $ciphertext.$aes->getTag();
        }
    }

    /**
     * Decrypt with AES-GCM and verify the 16-byte authentication tag (in constant time).
     *
     * @return string|false The plaintext, or false if authentication fails.
     */
    public static function gcmDecrypt(string $key, string $nonce, string $aad, string $ciphertext, string $tag): string|false
    {
        switch (self::backend('gcm', $key)) {
            case self::BACKEND_SODIUM:
                return sodium_crypto_aead_aes256gcm_decrypt($ciphertext.$tag, $aad, $nonce, $key);
            case self::BACKEND_OPENSSL:
                return openssl_decrypt($ciphertext, self::opensslName('gcm', $key), $key, OPENSSL_RAW_DATA, $nonce, $tag, $aad);
            default:
                // GCM with a 96-bit nonce encrypts from inc32(J0) = nonce || 2. Derive a candidate
                // plaintext without releasing it, then run the authenticated encryption direction
                // and compare its complete result in constant time. This avoids phpseclib's portable
                // GCM decrypt path, whose tag comparison is not constant-time.
                $plain = self::ctr($key, $nonce.pack('N', 2), $ciphertext);
                $verified = self::gcmEncrypt($key, $nonce, $aad, $plain);
                $ciphertextValid = hash_equals(substr($verified, 0, -16), $ciphertext);
                $tagValid = hash_equals(substr($verified, -16), $tag);
                return $ciphertextValid && $tagValid ? $plain : false;
        }
    }

    /**
     * Encrypt (or decrypt) with AES-CTR.
     *
     * @throws SrtpException If encryption fails.
     */
    public static function ctr(string $key, string $iv, string $data): string
    {
        if ($data === '') {
            return '';
        }
        switch (self::backend('ctr', $key)) {
            case self::BACKEND_OPENSSL:
                $result = openssl_encrypt($data, self::opensslName('ctr', $key), $key, OPENSSL_RAW_DATA, $iv);
                if ($result === false) {
                    throw new SrtpException('AES-CTR encryption failed!');
                }
                return $result;
            default:
                $aes = self::cipher('ctr', $key);
                $aes->setIV($iv);
                return $aes->encrypt($data);
        }
    }

    /**
     * @param 'gcm'|'ctr' $mode
     * @return self::BACKEND_*
     */
    private static function backend(string $mode, string $key): string
    {
        $sodium = $mode === 'gcm' && \strlen($key) === 32 && (self::$sodiumGcm ??= \function_exists('sodium_crypto_aead_aes256gcm_is_available') && sodium_crypto_aead_aes256gcm_is_available());
        $openssl = \extension_loaded('openssl') && (self::$opensslCiphers[$name = self::opensslName($mode, $key)] ??= \in_array($name, openssl_get_cipher_methods(), true));
        if (self::$backend !== null) {
            $available = match (self::$backend) {
                self::BACKEND_SODIUM => $sodium,
                self::BACKEND_OPENSSL => $openssl,
                self::BACKEND_PHPSECLIB => true,
            };
            if ($available) {
                return self::$backend;
            }
        }
        if ($sodium) {
            return self::BACKEND_SODIUM;
        }
        return $openssl ? self::BACKEND_OPENSSL : self::BACKEND_PHPSECLIB;
    }

    /** @param 'gcm'|'ctr' $mode */
    private static function opensslName(string $mode, string $key): string
    {
        return 'aes-'.(\strlen($key) * 8).'-'.$mode;
    }

    /** @param 'gcm'|'ctr' $mode */
    private static function cipher(string $mode, string $key): PhpseclibAes
    {
        $id = $mode.$key;
        if (isset(self::$ciphers[$id])) {
            return self::$ciphers[$id];
        }
        if (\count(self::$ciphers) >= self::MAX_CACHED_CIPHERS) {
            self::$ciphers = [];
        }
        $aes = new PhpseclibAes($mode);
        $aes->setKey($key);
        if ($mode === 'ctr') {
            $aes->disablePadding();
        }
        return self::$ciphers[$id] = $aes;
    }
}
