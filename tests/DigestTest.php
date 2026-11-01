<?php

declare(strict_types=1);

namespace Webrtc\Srtp\Test;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use ReflectionProperty;
use Webrtc\Srtp\Digest;

/**
 * Both backends of Digest (OpenSSL and the hash extension) give the digests of the hash extension, for every size.
 */
#[CoversClass(Digest::class)]
final class DigestTest extends TestCase
{
    /** @var array<'sha1'|'sha256', int> */
    private array $opensslFrom;

    protected function setUp(): void
    {
        $this->opensslFrom = (new ReflectionProperty(Digest::class, 'opensslFrom'))->getValue();
    }

    protected function tearDown(): void
    {
        (new ReflectionProperty(Digest::class, 'opensslFrom'))->setValue(null, $this->opensslFrom);
    }

    /** @return iterable<string, array{int}> */
    public static function backends(): iterable
    {
        yield 'OpenSSL' => [0];
        yield 'hash extension' => [PHP_INT_MAX];
    }

    #[DataProvider('backends')]
    public function testDigestsMatchTheHashExtension(int $opensslFrom): void
    {
        (new ReflectionProperty(Digest::class, 'opensslFrom'))->setValue(null, ['sha1' => $opensslFrom, 'sha256' => $opensslFrom]);
        foreach ([0, 1, 55, 63, 64, 65, 200, 1200, 1500, 70000] as $size) {
            $data = $size ? random_bytes($size) : "";
            self::assertSame(hash('sha256', $data, true), Digest::sha256($data), "SHA-256 of $size bytes");
            foreach ([0, 20, 64, 65, 100] as $keyLength) {
                $key = $keyLength ? random_bytes($keyLength) : "";
                self::assertSame(
                    hash_hmac('sha1', $data, $key, true),
                    Digest::hmacSha1($data, $key),
                    "HMAC-SHA1 of $size bytes with a $keyLength-byte key",
                );
            }
        }
    }
}
