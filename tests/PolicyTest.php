<?php

namespace Tests\Webrtc\Srtp;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Webrtc\Srtp\Enum\SrtpProfile;
use Webrtc\Srtp\Enum\SsrcType;
use Webrtc\Srtp\Exception\SrtpException;
use Webrtc\Srtp\Policy;
use Webrtc\Srtp\Srtp;

#[UsesClass(Srtp::class)]
#[CoversClass(Policy::class)]
class PolicyTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        Srtp::init();
    }

    public function testAllowRepeatTx()
    {
        $policy = new Policy();
        $this->assertFalse($policy->getAllowRepeatTx());

        $policy->setAllowRepeatTx(true);
        $this->assertTrue($policy->getAllowRepeatTx());

        $policy->setAllowRepeatTx(false);
        $this->assertFalse($policy->getAllowRepeatTx());

        $policy->setAllowRepeatTx(1);
        $this->assertTrue($policy->getAllowRepeatTx());

        $policy->setAllowRepeatTx( 0);
        $this->assertFalse($policy->getAllowRepeatTx());
    }

    public function testKey()
    {
        $key = random_bytes(30);

        $policy = new Policy();
        $this->assertNull($policy->getKey());

        $policy->setKey($key);
        $this->assertEquals($key, $policy->getKey());

        $policy->setKey();
        $this->assertNull($policy->getKey());

        // Key is too short.
        $this->expectException(SrtpException::class);
        $this->expectExceptionMessage('key must contain at least 30 bytes');
        $policy->setKey('0');
        $this->assertNull($policy->getKey());
    }

    public function testSrtpPolicy()
    {
        // Default profile.
        $policy = new Policy();
        $this->assertEquals(SrtpProfile::AES128_CM_SHA1_80, $policy->getSrtpProfile());

        // Valid user-specified profiles.
        $srtpProfiles = [
            ['srtp_profile' => SrtpProfile::AES128_CM_SHA1_80],
            ['srtp_profile' => SrtpProfile::AES128_CM_SHA1_32],
        ];
        foreach ($srtpProfiles as $profile) {
            $policy = new Policy($profile['srtp_profile']);
            $this->assertEquals($profile['srtp_profile'], $policy->getSrtpProfile());
        }
    }

    public function testSsrcType()
    {
        $policy = new Policy();
        $this->assertEquals(SsrcType::UNDEFINED, $policy->getSsrcType());

        $policy->setSsrcType(SsrcType::ANY_INBOUND);
        $this->assertEquals(SsrcType::ANY_INBOUND, $policy->getSsrcType());
    }

    public function testSsrcValue()
    {
        $policy = new Policy();
        $this->assertEquals(0, $policy->getSsrcValue());

        $policy->setSsrcValue(12345);
        $this->assertEquals(12345, $policy->getSsrcValue());
    }

    public function testWindowSize()
    {
        $policy = new Policy();
        $this->assertEquals(0, $policy->getWindowSize());

        $policy->setWindowSize(1024);
        $this->assertEquals(1024, $policy->getWindowSize());
    }
}