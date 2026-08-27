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
        // Resolve every parameter up front. Unsupported enum cases must fail here instead of
        // falling through to plausible-looking default key and tag sizes.
        self::parameters($srtpProfile);
        self::validateSsrcValue($ssrcValue);
        if ($key !== null) {
            $this->setKey($key);
        }
    }

    /**
     * @return array{key: int, salt: int, rtpTag: int, rtcpTag: int, aead: bool}
     * @throws SrtpValidateException If the profile is not implemented.
     */
    private static function parameters(SrtpProfile $profile): array
    {
        return match ($profile) {
            SrtpProfile::AES128_CM_SHA1_80 => [
                'key' => 16, 'salt' => 14, 'rtpTag' => 10, 'rtcpTag' => 10, 'aead' => false,
            ],
            SrtpProfile::AES128_CM_SHA1_32 => [
                'key' => 16, 'salt' => 14, 'rtpTag' => 4, 'rtcpTag' => 10, 'aead' => false,
            ],
            SrtpProfile::AEAD_AES_128_GCM => [
                'key' => 16, 'salt' => 12, 'rtpTag' => 16, 'rtcpTag' => 16, 'aead' => true,
            ],
            SrtpProfile::AEAD_AES_256_GCM => [
                'key' => 32, 'salt' => 12, 'rtpTag' => 16, 'rtcpTag' => 16, 'aead' => true,
            ],
            default => throw new SrtpValidateException("Unsupported SRTP profile: {$profile->name}"),
        };
    }

    /**
     * Master key length of a profile, in bytes.
     *
     * @throws SrtpValidateException If the profile is not implemented.
     */
    public static function keyLength(SrtpProfile $profile): int
    {
        return self::parameters($profile)['key'];
    }

    /**
     * Master salt length of a profile, in bytes.
     */
    public static function saltLength(SrtpProfile $profile): int
    {
        return self::parameters($profile)['salt'];
    }

    /**
     * Whether the profile uses an AEAD cipher, which authenticates without a separate HMAC.
     */
    public static function isAead(SrtpProfile $profile): bool
    {
        return self::parameters($profile)['aead'];
    }

    /**
     * Length of the authentication tag appended to protected RTP packets, in bytes.
     */
    public static function rtpTagLength(SrtpProfile $profile): int
    {
        return self::parameters($profile)['rtpTag'];
    }

    /**
     * Length of the authentication tag appended to protected RTCP packets, in bytes.
     *
     * SRTCP always uses the full 80-bit tag with the HMAC-SHA1 profiles.
     */
    public static function rtcpTagLength(SrtpProfile $profile): int
    {
        return self::parameters($profile)['rtcpTag'];
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
     *
     * @throws SrtpValidateException If no keying material is installed.
     */
    public function getMasterKey(): string
    {
        if ($this->key === null) {
            throw new SrtpValidateException('The SRTP policy has no key!');
        }
        return substr($this->key, 0, self::keyLength($this->srtpProfile));
    }

    /**
     * The master salt, i.e. the tail of the exported key material.
     *
     * @throws SrtpValidateException If no keying material is installed.
     */
    public function getMasterSalt(): string
    {
        if ($this->key === null) {
            throw new SrtpValidateException('The SRTP policy has no key!');
        }
        return substr($this->key, self::keyLength($this->srtpProfile));
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
        self::validateSsrcValue($ssrcValue);
        $this->ssrcValue = $ssrcValue;
    }

    public function getWindowSize(): int
    {
        return $this->windowSize;
    }

    public function setWindowSize(int $windowSize): void
    {
        if ($windowSize < 64) {
            throw new SrtpValidateException('The SRTP replay window must contain at least 64 packets.');
        }
        $this->windowSize = $windowSize;
    }

    /**
     * @throws SrtpValidateException If the value cannot be encoded as an unsigned 32-bit SSRC.
     */
    private static function validateSsrcValue(int $ssrcValue): void
    {
        if ($ssrcValue < 0 || $ssrcValue > 0xFFFFFFFF) {
            throw new SrtpValidateException('The SSRC must be an unsigned 32-bit integer.');
        }
    }
}
