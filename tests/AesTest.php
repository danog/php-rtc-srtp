<?php

declare(strict_types=1);

namespace Tests\Webrtc\Srtp;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Webrtc\Srtp\Aes;
use Webrtc\Srtp\AesCtrKey;
use Webrtc\Srtp\AesGcmKey;
use Webrtc\Srtp\Enum\SrtpProfile;
use Webrtc\Srtp\HmacSha1Key;
use Webrtc\Srtp\Policy;
use Webrtc\Srtp\Session;

/**
 * Every AES backend must give the same results: the phpseclib one is the reference, checked against pion/srtp by
 * {@see SessionTest}.
 */
#[CoversClass(Aes::class)]
#[CoversClass(AesGcmKey::class)]
#[CoversClass(AesCtrKey::class)]
#[CoversClass(HmacSha1Key::class)]
#[UsesClass(Session::class)]
#[UsesClass(Policy::class)]
#[UsesClass(\Webrtc\Srtp\Digest::class)]
class AesTest extends TestCase
{
    protected function tearDown(): void
    {
        Aes::$backend = null;
    }

    /** @return iterable<string, array{string, int}> */
    public static function backends(): iterable
    {
        foreach (self::fastBackends() as $backend) {
            foreach ([16, 32] as $keyLength) {
                yield "$backend, AES-".($keyLength * 8) => [$backend, $keyLength];
            }
        }
    }

    /**
     * The backends compared with phpseclib: madeline_crypto's only if the extension is loaded.
     *
     * @return list<Aes::BACKEND_*>
     */
    private static function fastBackends(): array
    {
        $backends = [Aes::BACKEND_SODIUM, Aes::BACKEND_OPENSSL];
        if (Aes::nativeAvailable()) {
            $backends[] = Aes::BACKEND_NATIVE;
        }
        return $backends;
    }

    /** @return iterable<string, array{Aes::BACKEND_*}> */
    public static function ctrBackends(): iterable
    {
        foreach ([Aes::BACKEND_OPENSSL, Aes::BACKEND_PHPSECLIB, ...(Aes::nativeAvailable() ? [Aes::BACKEND_NATIVE] : [])] as $backend) {
            yield $backend => [$backend];
        }
    }

    /**
     * @template T
     * @param callable(): T $operation
     * @return T
     */
    private static function with(string $backend, callable $operation): mixed
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

    #[DataProvider('ctrBackends')]
    public function testCtrMatchesTheReference(string $backend): void
    {
        foreach ([16, 32] as $keyLength) {
            $key = random_bytes($keyLength);
            $ctr = self::with($backend, static fn () => new AesCtrKey($key));
            $this->assertSame($backend, $ctr->getBackend());
            foreach ([1, 15, 16, 17, 1200] as $length) {
                // The counter wraps around in the low bits.
                $iv = random_bytes(14)."\xff\xff";
                $data = random_bytes($length);
                $reference = self::with(Aes::BACKEND_PHPSECLIB, static fn () => Aes::ctr($key, $iv, $data));
                $this->assertSame($reference, self::with($backend, static fn () => Aes::ctr($key, $iv, $data)));
                // The key object takes a new IV every time.
                $this->assertSame($reference, $ctr->apply($iv, $data));
                $this->assertSame($reference, $ctr->apply($iv, $data));
                $this->assertSame($data, $ctr->apply($iv, $reference));
            }
            $this->assertSame('', $ctr->apply(random_bytes(16), ''));
        }
    }

    /** RFC 3686 test vector #2 (AES-128-CTR). */
    #[DataProvider('ctrBackends')]
    public function testCtrKnownVector(string $backend): void
    {
        $ctr = self::with($backend, static fn () => new AesCtrKey(hex2bin('7e24067817fae0d743d6ce1f32539163')));
        $this->assertSame(
            '5104a106168a72d9790d41ee8edad388eb2e1efc46da57c8fce630df9141be28',
            bin2hex($ctr->apply(hex2bin('006cb6dbc0543b59da48d90b00000001'), hex2bin('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'))),
        );
    }

    /** NIST GCM test case 4 (AES-128, 60-byte plaintext, 20-byte AAD). */
    #[DataProvider('ctrBackends')]
    public function testGcmKnownVector(string $backend): void
    {
        $gcm = self::with($backend, static fn () => new AesGcmKey(hex2bin('feffe9928665731c6d6a8f9467308308')));
        $plaintext = hex2bin('d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39');
        $aad = hex2bin('feedfacedeadbeeffeedfacedeadbeefabaddad2');
        $nonce = hex2bin('cafebabefacedbaddecaf888');
        $sealed = $gcm->encrypt($nonce, $aad, $plaintext);
        $this->assertSame(
            '42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091'
            .'5bc94fbc3221a5db94fae95ae7121a47',
            bin2hex($sealed),
        );
        $this->assertSame($plaintext, $gcm->decrypt($nonce, $aad, substr($sealed, 0, -16), substr($sealed, -16)));
    }

    /** RFC 2202 test case 3, and random inputs against hash_hmac(). */
    public function testHmacSha1(): void
    {
        foreach ([false, ...(Aes::nativeAvailable() ? [true] : [])] as $native) {
            $hmac = new HmacSha1Key(str_repeat("\xaa", 20), $native);
            $this->assertSame('125d7342b9ac11cd91a39af48aa17b4f63f175d3', bin2hex($hmac->mac(str_repeat("\xdd", 50))));
            foreach ([0, 20, 64, 100] as $keyLength) {
                $key = $keyLength ? random_bytes($keyLength) : '';
                $hmac = new HmacSha1Key($key, $native);
                foreach ([0, 1, 64, 1200] as $length) {
                    $data = $length ? random_bytes($length) : '';
                    $this->assertSame(hash_hmac('sha1', $data, $key, true), $hmac->mac($data));
                }
            }
        }
    }

    /** The key objects are serialized as their key alone, and set up again. */
    public function testKeyObjectsSerializeTheirKeyOnly(): void
    {
        $key = random_bytes(16);
        $nonce = random_bytes(12);
        $gcm = new AesGcmKey($key);
        $copy = unserialize(serialize($gcm));
        $this->assertInstanceOf(AesGcmKey::class, $copy);
        $this->assertSame($gcm->encrypt($nonce, 'aad', 'payload'), $copy->encrypt($nonce, 'aad', 'payload'));
        $ctr = new AesCtrKey($key);
        $copy = unserialize(serialize($ctr));
        $this->assertInstanceOf(AesCtrKey::class, $copy);
        $this->assertSame($ctr->apply($nonce.'0000', 'payload'), $copy->apply($nonce.'0000', 'payload'));
        $hmac = new HmacSha1Key($key);
        $copy = unserialize(serialize($hmac));
        $this->assertInstanceOf(HmacSha1Key::class, $copy);
        $this->assertSame($hmac->mac('payload'), $copy->mac('payload'));
    }

    /** @return iterable<string, array{Aes::BACKEND_*, SrtpProfile}> */
    public static function sessionBackends(): iterable
    {
        foreach ([...self::fastBackends(), Aes::BACKEND_PHPSECLIB] as $backend) {
            foreach ([SrtpProfile::AES128_CM_SHA1_80, SrtpProfile::AEAD_AES_128_GCM, SrtpProfile::AEAD_AES_256_GCM] as $profile) {
                yield "$backend, {$profile->name}" => [$backend, $profile];
            }
        }
    }

    /**
     * A session gives the same packets whatever the backend, and goes on with another one once unserialized (a
     * session saved without the extension, loaded with it).
     */
    #[DataProvider('sessionBackends')]
    public function testSessionsGiveTheSamePacketsWithEveryBackend(string $backend, SrtpProfile $profile): void
    {
        $key = random_bytes(Policy::isAead($profile) ? ($profile === SrtpProfile::AEAD_AES_256_GCM ? 44 : 28) : 30);
        $packets = [];
        for ($seq = 0; $seq < 3; $seq++) {
            $packets[] = "\x80\x60".pack('nNN', $seq, 1234, 5678).random_bytes(100 * $seq + 1);
        }
        $rtcp = "\x80\xc8\x00\x06".pack('N', 5678).random_bytes(20);

        $reference = new Session(new Policy($profile, $key));
        $expected = array_map($reference->protect(...), $packets);
        $expectedRtcp = $reference->protectRtcp($rtcp);

        Aes::$backend = $backend;
        $session = new Session(new Policy($profile, $key));
        $receiver = new Session(new Policy($profile, $key));
        $this->assertSame($expected[0], $session->protect($packets[0]));
        $this->assertSame($packets[0], $receiver->unprotect($expected[0]));
        Aes::$backend = null;

        $serialized = serialize($session);
        $this->assertStringNotContainsString('AesGcmKey', $serialized);
        $this->assertStringNotContainsString('AesCtrKey', $serialized);
        $session = unserialize($serialized);
        $this->assertInstanceOf(Session::class, $session);
        $receiver = unserialize(serialize($receiver));
        $this->assertInstanceOf(Session::class, $receiver);
        for ($i = 1; $i < 3; $i++) {
            $this->assertSame($expected[$i], $session->protect($packets[$i]));
            $this->assertSame($packets[$i], $receiver->unprotect($expected[$i]));
        }
        $this->assertSame($expectedRtcp, $session->protectRtcp($rtcp));
        $this->assertSame($rtcp, $receiver->unprotectRtcp($expectedRtcp));
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
