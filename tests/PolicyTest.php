<?php

namespace Tests\Webrtc\Srtp;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Webrtc\Srtp\Enum\SrtpProfile;
use Webrtc\Srtp\Enum\SsrcType;
use Webrtc\Srtp\Exception\SrtpValidateException;
use Webrtc\Srtp\Policy;

#[CoversClass(Policy::class)]
#[UsesClass(\Webrtc\Srtp\Exception\SrtpValidateException::class)]
class PolicyTest extends TestCase
{
    public function testDefaultsToTheMandatoryProfile(): void
    {
        $this->assertSame(SrtpProfile::AES128_CM_SHA1_80, (new Policy())->getSrtpProfile());
    }

    /**
     * The keying material is the master key followed by the master salt. Getting these lengths
     * wrong silently derives the wrong session keys, so the split is asserted explicitly.
     *
     * @return array<string, array{SrtpProfile, int, int}>
     */
    public static function profiles(): array
    {
        return [
            'AES_CM_128_HMAC_SHA1_80' => [SrtpProfile::AES128_CM_SHA1_80, 16, 14],
            'AES_CM_128_HMAC_SHA1_32' => [SrtpProfile::AES128_CM_SHA1_32, 16, 14],
            'AEAD_AES_128_GCM' => [SrtpProfile::AEAD_AES_128_GCM, 16, 12],
            'AEAD_AES_256_GCM' => [SrtpProfile::AEAD_AES_256_GCM, 32, 12],
        ];
    }

    #[DataProvider('profiles')]
    public function testSplitsKeyingMaterialIntoMasterKeyAndSalt(
        SrtpProfile $profile,
        int $keyLength,
        int $saltLength
    ): void {
        $key = random_bytes($keyLength);
        $salt = random_bytes($saltLength);

        $policy = new Policy($profile, $key . $salt);

        $this->assertSame($keyLength, Policy::keyLength($profile));
        $this->assertSame($saltLength, Policy::saltLength($profile));
        $this->assertSame(bin2hex($key), bin2hex($policy->getMasterKey()));
        $this->assertSame(bin2hex($salt), bin2hex($policy->getMasterSalt()));
    }

    #[DataProvider('profiles')]
    public function testRejectsKeyingMaterialOfTheWrongLength(
        SrtpProfile $profile,
        int $keyLength,
        int $saltLength
    ): void {
        $this->expectException(SrtpValidateException::class);
        new Policy($profile, random_bytes($keyLength + $saltLength - 1));
    }

    public static function profileNames(): array
    {
        return array_map(
            static fn (array $row): array => [$row[0]],
            self::profiles()
        );
    }

    #[DataProvider('profileNames')]
    public function testKnowsWhichProfilesAreAead(SrtpProfile $profile): void
    {
        $this->assertSame(
            \in_array($profile, [SrtpProfile::AEAD_AES_128_GCM, SrtpProfile::AEAD_AES_256_GCM], true),
            Policy::isAead($profile)
        );
    }

    public function testRejectsAProfileWithNoImplementation(): void
    {
        $this->expectException(SrtpValidateException::class);
        new Policy(SrtpProfile::NULL_SHA1_80);
    }

    public function testProfileHelpersAlsoRejectUnsupportedProfiles(): void
    {
        $this->expectException(SrtpValidateException::class);
        Policy::rtpTagLength(SrtpProfile::NULL_SHA1_32);
    }

    public function testKeyCanBeSetAndCleared(): void
    {
        $key = random_bytes(30);
        $policy = new Policy();

        $this->assertNull($policy->getKey());

        $policy->setKey($key);
        $this->assertSame(bin2hex($key), bin2hex($policy->getKey()));

        $policy->setKey();
        $this->assertNull($policy->getKey());
    }

    public function testReadingMasterKeyWithoutMaterialThrows(): void
    {
        $this->expectException(SrtpValidateException::class);
        (new Policy())->getMasterKey();
    }

    public function testAllowRepeatTx(): void
    {
        $policy = new Policy();
        $this->assertFalse($policy->getAllowRepeatTx());

        $policy->setAllowRepeatTx(true);
        $this->assertTrue($policy->getAllowRepeatTx());

        $policy->setAllowRepeatTx(false);
        $this->assertFalse($policy->getAllowRepeatTx());
    }

    public function testSsrcType(): void
    {
        $policy = new Policy();
        $this->assertSame(SsrcType::UNDEFINED, $policy->getSsrcType());

        $policy->setSsrcType(SsrcType::ANY_INBOUND);
        $this->assertSame(SsrcType::ANY_INBOUND, $policy->getSsrcType());
    }

    public function testSsrcValue(): void
    {
        $policy = new Policy();
        $this->assertSame(0, $policy->getSsrcValue());

        $policy->setSsrcValue(12345);
        $this->assertSame(12345, $policy->getSsrcValue());
    }

    public function testWindowSize(): void
    {
        $policy = new Policy();
        $this->assertSame(1024, $policy->getWindowSize(), 'the default replay window');

        $policy->setWindowSize(4096);
        $this->assertSame(4096, $policy->getWindowSize());
    }

    public function testRejectsReplayWindowsBelowTheRfcMinimum(): void
    {
        $this->expectException(SrtpValidateException::class);
        (new Policy())->setWindowSize(63);
    }

    public function testRejectsSsrcOutsideTheUnsigned32BitRange(): void
    {
        $this->expectException(SrtpValidateException::class);
        (new Policy())->setSsrcValue(-1);
    }
}
