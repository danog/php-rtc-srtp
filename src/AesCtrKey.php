<?php

declare(strict_types=1);

namespace Webrtc\Srtp;

use danog\MadelineProto\Native\AesCtrKey as NativeAesCtrKey;
use phpseclib4\Crypt\AES as PhpseclibAes;
use Webrtc\Srtp\Exception\SrtpException;

/**
 * An AES-CTR key, set up once for all the packets it protects, each with its own IV (see {@see Aes} for the backends).
 *
 * It's serialized as the key alone: the backend is chosen again when it's unserialized.
 */
final class AesCtrKey
{
    /** @var Aes::BACKEND_* */
    private string $backend;
    private ?NativeAesCtrKey $native = null;
    private string $opensslName = '';
    private ?PhpseclibAes $phpseclib = null;

    /**
     * @param Aes::BACKEND_*|null $backend The backend to use, if not the fastest one.
     *
     * @throws SrtpException If the key isn't 16, 24 or 32 bytes long.
     */
    public function __construct(#[\SensitiveParameter] private string $key, ?string $backend = null)
    {
        $this->setUp($backend);
    }

    /** @param Aes::BACKEND_*|null $backend */
    private function setUp(?string $backend): void
    {
        $length = \strlen($this->key);
        if ($length !== 16 && $length !== 24 && $length !== 32) {
            throw new SrtpException('Invalid AES key length!');
        }
        $this->backend = $backend ?? Aes::backend('ctr', $length);
        $this->native = $this->backend === Aes::BACKEND_NATIVE ? new NativeAesCtrKey($this->key) : null;
        $this->opensslName = Aes::opensslName('ctr', $length);
        $this->phpseclib = null;
    }

    /**
     * Encrypt (or decrypt) with the keystream that starts from the 16-byte initial counter block $iv.
     *
     * @throws SrtpException If encryption fails.
     */
    public function apply(string $iv, string $data): string
    {
        if ($data === '') {
            return '';
        }
        if ($this->native !== null) {
            return $this->native->apply($iv, $data);
        }
        if ($this->backend === Aes::BACKEND_OPENSSL) {
            $result = openssl_encrypt($data, $this->opensslName, $this->key, OPENSSL_RAW_DATA, $iv);
            if ($result === false) {
                throw new SrtpException('AES-CTR encryption failed!');
            }
            return $result;
        }
        $aes = $this->phpseclib ??= Aes::phpseclib('ctr', $this->key);
        $aes->setIV($iv);
        return $aes->encrypt($data);
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
        $this->setUp(null);
    }

    public function __debugInfo(): array
    {
        return ['backend' => $this->backend];
    }
}
