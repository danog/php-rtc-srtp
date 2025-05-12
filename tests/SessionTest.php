<?php

namespace Tests\Webrtc\Srtp;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Webrtc\Exception\InvalidArgumentException;
use Webrtc\Srtp\Enum\SrtpProfile;
use Webrtc\Srtp\Enum\SsrcType;
use Webrtc\Srtp\Exception\SrtpException;
use Webrtc\Srtp\Exception\SrtpValidateException;
use Webrtc\Srtp\Policy;
use Webrtc\Srtp\Session;
use Webrtc\Srtp\Srtp;

#[UsesClass(SrtpValidateException::class)]
#[UsesClass(Policy::class)]
#[UsesClass(Srtp::class)]
#[CoversClass(Session::class)]
class SessionTest extends TestCase
{
    private string $rtp;
    private string $rtcp;
    private array $profiles = [
        [
            "srtp_profile" => SrtpProfile::AES128_CM_SHA1_32,
            "protected_rtcp_length" => 42,
            "key_length" => 30,
            "protected_rtp_length" => 176
        ],
        [
            "srtp_profile" => SrtpProfile::AES128_CM_SHA1_80,
            "protected_rtcp_length" => 42,
            "key_length" => 30,
            "protected_rtp_length" => 182
        ]
    ];

    protected function setUp(): void
    {
        parent::setUp();

        Srtp::init();
        $this->updateProfiles();
        $this->rtp = "\x80\x08\x00\x00"
            . "\x00\x00\x00\x00"
            . "\x00\x00\x30\x39"
            . str_repeat("\xd4", 160);

        $this->rtcp = "\x80\xc8\x00\x06\xf3\xcb\x20\x01\x83\xab\x03\xa1\xeb\x02\x0b\x3a"
            . "\x00\x00\x94\x20\x00\x00\x00\x9e\x00\x00\x9b\x88";

    }

    public function testNoKey()
    {
        $policy = new Policy(ssrcType: SsrcType::ANY_OUTBOUND);

        $this->expectException(SrtpValidateException::class);
        $this->expectExceptionMessage('unsupported parameter');
        new Session($policy);
    }

    public function testAddRemoveStream()
    {
        foreach ($this->profiles as $profile) {
            $key = random_bytes($profile['key_length']);

            // Protect $this->rtp
            $txSession = new Session(
                new Policy(
                    srtpProfile: $profile['srtp_profile'],
                    key: $key,
                    ssrcType: SsrcType::SPECIFIC,
                    ssrcValue: 12345
                )
            );
            $protected = $txSession->protect($this->rtp);
            $this->assertEquals($profile['protected_rtp_length'], strlen($protected));

            $rxSession = new Session();
            $rxSession->addStream(
                new Policy(
                    srtpProfile: $profile['srtp_profile'],
                    key: $key,
                    ssrcType: SsrcType::SPECIFIC,
                    ssrcValue: 12345
                )
            );
            $unprotected = $rxSession->unprotect($protected);
            $this->assertEquals($this->rtp, $unprotected);

            // Remove stream
            $rxSession->removeStream(12345);

            // Try removing stream again
            $this->expectException(SrtpValidateException::class);
            $this->expectExceptionMessage('no appropriate context found');
            $rxSession->removeStream(12345);
        }
    }

    public function testRtpAnySsrc()
    {
        foreach ($this->profiles as $profile) {
            $key = random_bytes($profile['key_length']);

            // Protect $this->rtp
            $txSession = new Session(
                new Policy(
                    srtpProfile: $profile['srtp_profile'],
                    key: $key,
                    ssrcType: SsrcType::ANY_OUTBOUND
                )
            );
            $protected = $txSession->protect($this->rtp);
            $this->assertEquals($profile['protected_rtp_length'], strlen($protected));

            // Bad type
            $this->expectException(SrtpException::class);
            $this->expectExceptionMessage('unsupported parameter');
            $txSession->protect(4567);

            // Bad length
            $this->expectException(InvalidArgumentException::class);
            $this->expectExceptionMessage('packet is too long');
            $txSession->protect(str_repeat('0', 1500));

            // Unprotect $this->rtp
            $rxSession = new Session(
                new Policy(
                    srtpProfile: $profile['srtp_profile'],
                    key: $key,
                    ssrcType: SsrcType::ANY_INBOUND
                )
            );
            $unprotected = $rxSession->unprotect($protected);
            $this->assertEquals($this->rtp, $unprotected);
        }
    }

    public function testRtcpAnySsrc()
    {
        foreach ($this->profiles as $profile) {
            $key = random_bytes($profile['key_length']);

            // Protect $this->rtcp
            $txSession = new Session(
                new Policy(
                    srtpProfile: $profile['srtp_profile'],
                    key: $key,
                    ssrcType: SsrcType::ANY_OUTBOUND
                )
            );
            $protected = $txSession->protectRtcp($this->rtcp);
            $this->assertEquals($profile['protected_rtcp_length'], strlen($protected));

            // Bad type
            $this->expectException(SrtpException::class);
            $this->expectExceptionMessage('unsupported parameter');
            $txSession->protectRtcp(4567);

            // Bad length
            $this->expectException(InvalidArgumentException::class);
            $this->expectExceptionMessage('packet is too long');
            $txSession->protectRtcp(str_repeat('0', 1500));

            // Unprotect $this->rtcp
            $rxSession = new Session(
                new Policy(
                    srtpProfile: $profile['srtp_profile'],
                    key: $key,
                    ssrcType: SsrcType::ANY_INBOUND
                )
            );
            $unprotected = $rxSession->unprotectRtcp($protected);
            $this->assertEquals($this->rtcp, $unprotected);
        }
    }

    public function testRtpSpecificSsrc()
    {
        foreach ($this->profiles as $profile) {
            $key = random_bytes($profile['key_length']);

            // Protect $this->rtp
            $txSession = new Session(
                new Policy(
                    srtpProfile: $profile['srtp_profile'],
                    key: $key,
                    ssrcType: SsrcType::SPECIFIC,
                    ssrcValue: 12345
                )
            );
            $protected = $txSession->protect($this->rtp);
            $this->assertEquals($profile['protected_rtp_length'], strlen($protected));

            // Unprotect $this->rtp
            $rxSession = new Session(
                new Policy(
                    srtpProfile: $profile['srtp_profile'],
                    key: $key,
                    ssrcType: SsrcType::SPECIFIC,
                    ssrcValue: 12345
                )
            );
            $unprotected = $rxSession->unprotect($protected);
            $this->assertEquals($this->rtp, $unprotected);
        }
    }

    private function updateProfiles(): void
    {
        try {
            new Policy(srtpProfile: SrtpProfile::AEAD_AES_128_GCM);
            $this->profiles = array_merge([
                [
                    "srtp_profile" => SrtpProfile::AEAD_AES_256_GCM,
                    "protected_rtcp_length" => 48,
                    "key_length" => 44,
                    "protected_rtp_length" => 188
                ],
                [
                    "srtp_profile" => SrtpProfile::AEAD_AES_128_GCM,
                    "protected_rtcp_length" => 48,
                    "key_length" => 28,
                    "protected_rtp_length" => 188
                ],
            ], $this->profiles);
        } catch (\Throwable) {
        }
    }
}
