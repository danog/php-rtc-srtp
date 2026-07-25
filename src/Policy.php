<?php

/**
 * This file is part of the PHP WebRTC package, vendored and modified for MadelineProto.
 *
 * (c) Amin Yazdanpanah <https://www.aminyazdanpanah.com/#contact>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Webrtc\Srtp;

use Webrtc\Srtp\Enum\SrtpProfile;
use Webrtc\Srtp\Enum\SsrcType;
use Webrtc\Srtp\Exception\SrtpValidateException;

/**
 * Cryptographic policy of an SRTP stream.
 *
 * Upstream this was a thin wrapper around a libsrtp `srtp_policy_t`; it is now a plain value
 * object, since {@see Session} implements SRTP directly in PHP.
 */
class Policy
{
    /** Master key concatenated with the master salt, as produced by the DTLS key exporter. */
    private ?string $key = null;

    private bool $allowRepeatTx = false;

    private int $windowSize = 1024;

    /**
     * @throws SrtpValidateException If the profile is not supported.
     */
    public function __construct(
        private readonly SrtpProfile $srtpProfile = SrtpProfile::AES128_CM_SHA1_80,
        ?string $key = null,
        private SsrcType $ssrcType = SsrcType::UNDEFINED,
        private int $ssrcValue = 0,
    ) {
        if (self::keyLength($srtpProfile) === null) {
            throw new SrtpValidateException("Unsupported SRTP profile: {$srtpProfile->name}");
        }
        if ($key !== null) {
            $this->setKey($key);
        }
    }

    /**
     * Master key length of a profile, in bytes, or null if the profile is not implemented.
     */
    public static function keyLength(SrtpProfile $profile): ?int
    {
        return match ($profile) {
            SrtpProfile::AES128_CM_SHA1_80,
            SrtpProfile::AES128_CM_SHA1_32,
            SrtpProfile::AEAD_AES_128_GCM => 16,
            SrtpProfile::AEAD_AES_256_GCM => 32,
            default => null,
        };
    }

    /**
     * Master salt length of a profile, in bytes.
     */
    public static function saltLength(SrtpProfile $profile): int
    {
        return match ($profile) {
            SrtpProfile::AEAD_AES_128_GCM, SrtpProfile::AEAD_AES_256_GCM => 12,
            default => 14,
        };
    }

    /**
     * Whether the profile uses an AEAD cipher, which authenticates without a separate HMAC.
     */
    public static function isAead(SrtpProfile $profile): bool
    {
        return $profile === SrtpProfile::AEAD_AES_128_GCM || $profile === SrtpProfile::AEAD_AES_256_GCM;
    }

    /**
     * Length of the authentication tag appended to protected RTP packets, in bytes.
     */
    public static function rtpTagLength(SrtpProfile $profile): int
    {
        return match ($profile) {
            SrtpProfile::AES128_CM_SHA1_32 => 4,
            SrtpProfile::AEAD_AES_128_GCM, SrtpProfile::AEAD_AES_256_GCM => 16,
            default => 10,
        };
    }

    /**
     * Length of the authentication tag appended to protected RTCP packets, in bytes.
     *
     * SRTCP always uses the full 80-bit tag with the HMAC-SHA1 profiles.
     */
    public static function rtcpTagLength(SrtpProfile $profile): int
    {
        return self::isAead($profile) ? 16 : 10;
    }

    public function getAllowRepeatTx(): bool
    {
        return $this->allowRepeatTx;
    }

    public function setAllowRepeatTx(bool $allowRepeatTx): void
    {
        $this->allowRepeatTx = $allowRepeatTx;
    }

    /**
     * @throws SrtpValidateException If the key does not match the profile's expected length.
     */
    public function setKey(?string $key = null): void
    {
        if ($key !== null) {
            $expected = self::keyLength($this->srtpProfile) + self::saltLength($this->srtpProfile);
            if (\strlen($key) !== $expected) {
                throw new SrtpValidateException(
                    "Invalid SRTP key length: expected $expected bytes, got ".\strlen($key)
                );
            }
        }
        $this->key = $key;
    }

    public function getKey(): ?string
    {
        return $this->key;
    }

    /**
     * The master key, without the trailing master salt.
     */
    public function getMasterKey(): string
    {
        return substr((string) $this->key, 0, (int) self::keyLength($this->srtpProfile));
    }

    /**
     * The master salt, i.e. the tail of the exported key material.
     */
    public function getMasterSalt(): string
    {
        return substr((string) $this->key, (int) self::keyLength($this->srtpProfile));
    }

    public function getSrtpProfile(): SrtpProfile
    {
        return $this->srtpProfile;
    }

    public function getSsrcType(): SsrcType
    {
        return $this->ssrcType;
    }

    public function setSsrcType(SsrcType $ssrcType): void
    {
        $this->ssrcType = $ssrcType;
    }

    public function getSsrcValue(): int
    {
        return $this->ssrcValue;
    }

    public function setSsrcValue(int $ssrcValue): void
    {
        $this->ssrcValue = $ssrcValue;
    }

    public function getWindowSize(): int
    {
        return $this->windowSize;
    }

    public function setWindowSize(int $windowSize): void
    {
        $this->windowSize = $windowSize;
    }
}
