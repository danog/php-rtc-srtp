<?php

declare(strict_types=1);

namespace Tests\Webrtc\Srtp;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Webrtc\Srtp\Aes;

/**
 * Every AES backend must give the same results: the phpseclib one is the reference, checked against pion/srtp by
 * {@see SessionTest}.
 */
#[CoversClass(Aes::class)]
class AesTest extends TestCase
{
    protected function tearDown(): void
    {
        Aes::$backend = null;
    }

    /** @return iterable<string, array{string, int}> */
    public static function backends(): iterable
    {
        foreach ([Aes::BACKEND_SODIUM, Aes::BACKEND_OPENSSL] as $backend) {
            foreach ([16, 32] as $keyLength) {
                yield "$backend, AES-".($keyLength * 8) => [$backend, $keyLength];
            }
        }
    }

    /**
     * @param callable(): string $operation
     */
    private static function with(string $backend, callable $operation): string|false
    {
        Aes::$backend = $backend;
        try {
            return $operation();
        } finally {
            Aes::$backend = null;
        }
    }

    #[DataProvider('backends')]
    public function testGcmEncryptionMatchesTheReference(string $backend, int $keyLength): void
    {
        $key = random_bytes($keyLength);
        $nonce = random_bytes(12);
        foreach (['', 'x', random_bytes(1200)] as $plaintext) {
            $aad = random_bytes(12);
            $reference = self::with(Aes::BACKEND_PHPSECLIB, static fn () => Aes::gcmEncrypt($key, $nonce, $aad, $plaintext));
            $this->assertSame($reference, self::with($backend, static fn () => Aes::gcmEncrypt($key, $nonce, $aad, $plaintext)));
        }
    }

    #[DataProvider('backends')]
    public function testGcmDecryptionAuthenticates(string $backend, int $keyLength): void
    {
        $key = random_bytes($keyLength);
        $nonce = random_bytes(12);
        $aad = random_bytes(12);
        $plaintext = random_bytes(1200);
        $sealed = self::with(Aes::BACKEND_PHPSECLIB, static fn () => Aes::gcmEncrypt($key, $nonce, $aad, $plaintext));
        $ciphertext = substr($sealed, 0, -16);
        $tag = substr($sealed, -16);

        foreach ([$backend, Aes::BACKEND_PHPSECLIB] as $decrypt) {
            $this->assertSame($plaintext, self::with($decrypt, static fn () => Aes::gcmDecrypt($key, $nonce, $aad, $ciphertext, $tag)));
            $tampered = $ciphertext;
            $tampered[100] = \chr(\ord($tampered[100]) ^ 1);
            $this->assertFalse(self::with($decrypt, static fn () => Aes::gcmDecrypt($key, $nonce, $aad, $tampered, $tag)));
            $this->assertFalse(self::with($decrypt, static fn () => Aes::gcmDecrypt($key, $nonce, $aad.'x', $ciphertext, $tag)));
            $this->assertFalse(self::with($decrypt, static fn () => Aes::gcmDecrypt($key, $nonce, $aad, $ciphertext, str_repeat("\0", 16))));
        }
    }

    public function testCtrMatchesTheReference(): void
    {
        foreach ([16, 32] as $keyLength) {
            $key = random_bytes($keyLength);
            $iv = random_bytes(14)."\0\0";
            $data = random_bytes(1200);
            $reference = self::with(Aes::BACKEND_PHPSECLIB, static fn () => Aes::ctr($key, $iv, $data));
            $this->assertSame($reference, self::with(Aes::BACKEND_OPENSSL, static fn () => Aes::ctr($key, $iv, $data)));
            // A new IV restarts the keystream.
            $this->assertSame($reference, self::with(Aes::BACKEND_PHPSECLIB, static fn () => Aes::ctr($key, $iv, $data)));
            $this->assertSame('', Aes::ctr($key, $iv, ''));
        }
    }

    public function testTheFastestBackendIsUsedByDefault(): void
    {
        $key = random_bytes(16);
        $nonce = random_bytes(12);
        $this->assertSame(
            self::with(Aes::BACKEND_PHPSECLIB, static fn () => Aes::gcmEncrypt($key, $nonce, 'aad', 'payload')),
            Aes::gcmEncrypt($key, $nonce, 'aad', 'payload'),
        );
    }
}
