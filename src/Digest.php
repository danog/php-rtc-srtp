<?php

declare(strict_types=1);

namespace Webrtc\Srtp;

use danog\MadelineProto\Native\Hash;

/**
 * SHA-256 and HMAC-SHA1 of packets, with the faster backend for their size.
 *
 * madeline_crypto 0.5+ hashes faster than both, if loaded (for HMAC-SHA1, see {@see HmacSha1Key}).
 *
 * OpenSSL costs a fixed overhead per call (from ~250 ns to several microseconds with OpenSSL 3's providers), then
 * uses the CPU's SHA instructions. PHP's hash extension has no such overhead, but uses SHA instructions only on x86
 * with SHA-NI, and only for SHA-256: elsewhere it's portable C. For a 1200-byte packet, OpenSSL is 5.6x faster for
 * SHA-256 and 2x for HMAC-SHA1 on an Apple M-series CPU, while hash() is 2x faster on an Intel N100. So the size from
 * which OpenSSL is faster is measured once per process, for each algorithm.
 *
 * @internal
 */
final class Digest
{
    /** @var array<'sha1'|'sha256', int> The size from which OpenSSL is faster, per algorithm. */
    private static array $opensslFrom = [];

    /**
     * Whether to use madeline_crypto (null: if available).
     *
     * @internal For tests.
     */
    public static ?bool $native = null;

    public static function sha256(string $data): string
    {
        if (self::$native ??= Aes::nativeAvailable()) {
            return Hash::digest('sha256', $data);
        }
        if (\strlen($data) >= (self::$opensslFrom['sha256'] ??= self::measureOpensslFrom('sha256'))) {
            $digest = openssl_digest($data, 'sha256', true);
            if ($digest !== false) {
                return $digest;
            }
        }
        return hash('sha256', $data, true);
    }

    /** HMAC-SHA1 (RFC 2104): with OpenSSL, two digests. */
    public static function hmacSha1(string $data, #[\SensitiveParameter] string $key): string
    {
        if (64 + \strlen($data) >= (self::$opensslFrom['sha1'] ??= self::measureOpensslFrom('sha1'))) {
            $block = \strlen($key) > 64 ? hash('sha1', $key, true) : $key;
            $block = str_pad($block, 64, "\0");
            $inner = openssl_digest(($block ^ str_repeat("\x36", 64)).$data, 'sha1', true);
            $digest = $inner === false ? false : openssl_digest(($block ^ str_repeat("\x5c", 64)).$inner, 'sha1', true);
            if ($digest !== false) {
                return $digest;
            }
        }
        return hash_hmac('sha1', $data, $key, true);
    }

    /**
     * The smallest of a few sizes from which OpenSSL hashes faster than hash() here.
     *
     * @param 'sha1'|'sha256' $algo
     */
    private static function measureOpensslFrom(string $algo): int
    {
        if (!\function_exists('openssl_digest') || !\in_array($algo, openssl_get_md_methods(), true)) {
            return PHP_INT_MAX;
        }
        foreach ([64, 256, 1024, 4096, 16384, 65536] as $size) {
            $data = str_repeat("\x5c", $size);
            $calls = max(2, intdiv(32768, $size));
            $hash = $openssl = PHP_INT_MAX;
            for ($round = 0; $round < 3; $round++) {
                $start = hrtime(true);
                for ($i = 0; $i < $calls; $i++) {
                    hash($algo, $data, true);
                }
                $hash = min($hash, hrtime(true) - $start);
                $start = hrtime(true);
                for ($i = 0; $i < $calls; $i++) {
                    openssl_digest($data, $algo, true);
                }
                $openssl = min($openssl, hrtime(true) - $start);
            }
            if ($openssl < $hash) {
                return $size;
            }
        }
        return PHP_INT_MAX;
    }
}
