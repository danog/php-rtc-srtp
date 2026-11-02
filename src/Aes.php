<?php

declare(strict_types=1);

namespace Webrtc\Srtp;

use danog\MadelineProto\Native\Crypto;
use phpseclib4\Crypt\AES as PhpseclibAes;
use Webrtc\Srtp\Exception\SrtpException;

/**
 * The AES primitives of SRTP (GCM and CTR), using the fastest implementation available.
 *
 * MadelineProto's madeline_crypto extension (0.5+) is used if loaded: its key objects keep the key schedule, so a
 * packet costs no setup. Otherwise libsodium is used for AES-256-GCM, if the CPU supports it; OpenSSL for everything
 * else; phpseclib if OpenSSL isn't available.
 *
 * Every packet is protected with a different nonce, but with the same few keys: {@see AesGcmKey} and
 * {@see AesCtrKey} choose their backend and set up the key once, when they're created. The static methods keep
 * a key object for each of the last few keys they were called with.
 *
 * @internal
 */
final class Aes
{
    public const BACKEND_NATIVE = 'native';
    public const BACKEND_SODIUM = 'sodium';
    public const BACKEND_OPENSSL = 'openssl';
    public const BACKEND_PHPSECLIB = 'phpseclib';

    /** How many key objects the static methods keep, at most. */
    private const MAX_CACHED_KEYS = 64;

    /**
     * The backend to use, instead of the fastest available one (if available): for tests.
     *
     * Read when a key object is created.
     *
     * @var self::BACKEND_*|null
     */
    public static ?string $backend = null;

    /** @var array<string, AesGcmKey|AesCtrKey> Key objects of the static methods, by backend, mode and key. */
    private static array $keys = [];

    private static ?bool $native = null;
    private static ?bool $sodiumGcm = null;
    /** @var array<string, bool> Whether OpenSSL supports a cipher, by name. */
    private static array $opensslCiphers = [];

    /** Whether the key objects of madeline_crypto 0.5+ are available. */
    public static function nativeAvailable(): bool
    {
        return self::$native ??= \extension_loaded('madeline_crypto')
            && version_compare(Crypto::version(), '0.5.0', '>=');
    }

    /**
     * Encrypt with AES-GCM, returning the ciphertext followed by the 16-byte authentication tag.
     *
     * @throws SrtpException If encryption fails.
     */
    public static function gcmEncrypt(#[\SensitiveParameter] string $key, string $nonce, string $aad, string $plaintext): string
    {
        return self::gcmKey($key)->encrypt($nonce, $aad, $plaintext);
    }

    /**
     * Decrypt with AES-GCM and verify the 16-byte authentication tag (in constant time).
     *
     * @return string|false The plaintext, or false if authentication fails.
     */
    public static function gcmDecrypt(#[\SensitiveParameter] string $key, string $nonce, string $aad, string $ciphertext, string $tag): string|false
    {
        return self::gcmKey($key)->decrypt($nonce, $aad, $ciphertext, $tag);
    }

    /**
     * Encrypt (or decrypt) with AES-CTR.
     *
     * @throws SrtpException If encryption fails.
     */
    public static function ctr(#[\SensitiveParameter] string $key, string $iv, string $data): string
    {
        $id = (self::$backend ?? '')."\0ctr".$key;
        $ctr = self::$keys[$id] ?? null;
        if (!$ctr instanceof AesCtrKey) {
            $ctr = new AesCtrKey($key);
            self::cache($id, $ctr);
        }
        return $ctr->apply($iv, $data);
    }

    private static function gcmKey(#[\SensitiveParameter] string $key): AesGcmKey
    {
        $id = (self::$backend ?? '')."\0gcm".$key;
        $gcm = self::$keys[$id] ?? null;
        if (!$gcm instanceof AesGcmKey) {
            $gcm = new AesGcmKey($key);
            self::cache($id, $gcm);
        }
        return $gcm;
    }

    private static function cache(string $id, AesGcmKey|AesCtrKey $key): void
    {
        if (\count(self::$keys) >= self::MAX_CACHED_KEYS) {
            self::$keys = [];
        }
        self::$keys[$id] = $key;
    }

    /**
     * The backend for a key: called once per key object.
     *
     * @internal
     *
     * @param 'gcm'|'ctr' $mode
     * @return self::BACKEND_*
     */
    public static function backend(string $mode, int $keyLength): string
    {
        $native = self::nativeAvailable();
        $sodium = $mode === 'gcm' && $keyLength === 32 && (self::$sodiumGcm ??= \function_exists('sodium_crypto_aead_aes256gcm_is_available') && sodium_crypto_aead_aes256gcm_is_available());
        $openssl = \extension_loaded('openssl') && (self::$opensslCiphers[$name = self::opensslName($mode, $keyLength)] ??= \in_array($name, openssl_get_cipher_methods(), true));
        if (self::$backend !== null) {
            $available = match (self::$backend) {
                self::BACKEND_NATIVE => $native,
                self::BACKEND_SODIUM => $sodium,
                self::BACKEND_OPENSSL => $openssl,
                self::BACKEND_PHPSECLIB => true,
            };
            if ($available) {
                return self::$backend;
            }
        }
        if ($native) {
            return self::BACKEND_NATIVE;
        }
        if ($sodium) {
            return self::BACKEND_SODIUM;
        }
        return $openssl ? self::BACKEND_OPENSSL : self::BACKEND_PHPSECLIB;
    }

    /**
     * @internal
     *
     * @param 'gcm'|'ctr' $mode
     */
    public static function opensslName(string $mode, int $keyLength): string
    {
        return 'aes-'.($keyLength * 8).'-'.$mode;
    }

    /**
     * @internal
     *
     * @param 'gcm'|'ctr' $mode
     */
    public static function phpseclib(string $mode, #[\SensitiveParameter] string $key): PhpseclibAes
    {
        $aes = new PhpseclibAes($mode);
        $aes->setKey($key);
        if ($mode === 'ctr') {
            $aes->disablePadding();
        }
        return $aes;
    }
}
