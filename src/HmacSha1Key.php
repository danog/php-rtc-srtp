<?php

declare(strict_types=1);

namespace Webrtc\Srtp;

use danog\MadelineProto\Native\Hmac;

/**
 * An HMAC-SHA1 key, set up once for all the packets it authenticates.
 *
 * With madeline_crypto 0.5+, the keyed inner and outer states are computed once; otherwise {@see Digest::hmacSha1()}.
 * It's serialized as the key alone.
 *
 * @internal
 */
final class HmacSha1Key
{
    private ?Hmac $native = null;

    public function __construct(#[\SensitiveParameter] private string $key, ?bool $native = null)
    {
        $this->setUp($native);
    }

    private function setUp(?bool $native): void
    {
        $this->native = ($native ?? Aes::nativeAvailable()) ? new Hmac('sha1', $this->key) : null;
    }

    public function mac(string $data): string
    {
        return $this->native !== null
            ? $this->native->mac($data)
            : Digest::hmacSha1($data, $this->key);
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
        $this->setUp(null);
    }

    public function __debugInfo(): array
    {
        return ['native' => $this->native !== null];
    }
}
