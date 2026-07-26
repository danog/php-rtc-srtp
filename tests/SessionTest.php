<?php

namespace Tests\Webrtc\Srtp;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Webrtc\Srtp\Enum\SrtpProfile;
use Webrtc\Srtp\Exception\SrtpException;
use Webrtc\Srtp\Policy;
use Webrtc\Srtp\Session;

/**
 * Checks the pure-PHP SRTP implementation against pion/srtp.
 *
 * The point of going through another implementation is that a protect/unprotect round trip
 * inside one codebase passes just as happily when both halves share a misreading of the
 * spec. Every wire-format assertion here is anchored to bytes pion produced.
 */
#[CoversClass(Session::class)]
#[UsesClass(Policy::class)]
class SessionTest extends TestCase
{
    /**
     * Master key followed by master salt, the layout DTLS exports keying material in.
     *
     * The salt is 14 bytes for the counter-mode profiles but only 12 for the AEAD ones
     * (RFC 7714 section 8.3), so the material is sized per profile rather than shared.
     */
    private const KEY_CM_128 = 'e1f97a0d3e018be0d64fa32c06de41390ec675ad498afeebb6960b3aabe6';
    private const KEY_GCM_128 = 'e1f97a0d3e018be0d64fa32c06de41390ec675ad498afeebb6960b3a';
    private const KEY_GCM_256 = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
        . '202122232425262728292a2b';

    /** A minimal RTP packet: version 2, payload type 15, sequence 0x1234, ssrc 0xcafebabe. */
    private const RTP = '800f1234decafbaddeadbeefcafebabe';

    private ?ReferencePeer $peer = null;

    protected function tearDown(): void
    {
        $this->peer?->stop();
        $this->peer = null;

        parent::tearDown();
    }

    /**
     * @return array<string, array{SrtpProfile, string, string}>
     */
    public static function profiles(): array
    {
        return [
            'AES_CM_128_HMAC_SHA1_80' => [SrtpProfile::AES128_CM_SHA1_80, 'AES_CM_128_HMAC_SHA1_80', self::KEY_CM_128],
            'AES_CM_128_HMAC_SHA1_32' => [SrtpProfile::AES128_CM_SHA1_32, 'AES_CM_128_HMAC_SHA1_32', self::KEY_CM_128],
            'AEAD_AES_128_GCM' => [SrtpProfile::AEAD_AES_128_GCM, 'AEAD_AES_128_GCM', self::KEY_GCM_128],
            'AEAD_AES_256_GCM' => [SrtpProfile::AEAD_AES_256_GCM, 'AEAD_AES_256_GCM', self::KEY_GCM_256],
        ];
    }

    private static function rtcpPacket(): string
    {
        // A sender report: version 2, no report blocks, ssrc 0xf3cb2001, followed by the
        // NTP/RTP timestamps and the packet and octet counts.
        return hex2bin('80c80006f3cb200183ab03a1eb020b3a000094200000009e00009b88');
    }

    #[DataProvider('profiles')]
    public function testProtectMatchesTheReferenceImplementation(
        SrtpProfile $profile,
        string $name,
        string $keyHex
    ): void {
        $key = hex2bin($keyHex);
        $packet = hex2bin(self::RTP);

        $ours = $this->session($profile, $key)->protect($packet);
        $theirs = $this->peer()->protect($name, $key, $packet);

        $this->assertSame(
            bin2hex($theirs),
            bin2hex($ours),
            "protected RTP under $name must be byte-identical to the reference implementation"
        );
    }

    #[DataProvider('profiles')]
    public function testUnprotectsWhatTheReferenceImplementationProduced(
        SrtpProfile $profile,
        string $name,
        string $keyHex
    ): void {
        $key = hex2bin($keyHex);
        $packet = hex2bin(self::RTP);

        $protected = $this->peer()->protect($name, $key, $packet);

        $this->assertSame(
            bin2hex($packet),
            bin2hex($this->session($profile, $key)->unprotect($protected)),
            "RTP protected by the reference implementation under $name must decrypt back"
        );
    }

    #[DataProvider('profiles')]
    public function testTheReferenceImplementationUnprotectsWhatWeProduced(
        SrtpProfile $profile,
        string $name,
        string $keyHex
    ): void {
        $key = hex2bin($keyHex);
        $packet = hex2bin(self::RTP);

        $protected = $this->session($profile, $key)->protect($packet);

        $this->assertSame(
            bin2hex($packet),
            bin2hex($this->peer()->unprotect($name, $key, $protected)),
            "the reference implementation must accept RTP we protected under $name"
        );
    }

    #[DataProvider('profiles')]
    public function testProtectRtcpMatchesTheReferenceImplementation(
        SrtpProfile $profile,
        string $name,
        string $keyHex
    ): void {
        $key = hex2bin($keyHex);
        $packet = self::rtcpPacket();

        $ours = $this->session($profile, $key)->protectRtcp($packet);
        $theirs = $this->peer()->protectRtcp($name, $key, $packet);

        $this->assertSame(
            bin2hex($theirs),
            bin2hex($ours),
            "protected RTCP under $name must be byte-identical to the reference implementation"
        );
    }

    #[DataProvider('profiles')]
    public function testUnprotectsRtcpFromTheReferenceImplementation(
        SrtpProfile $profile,
        string $name,
        string $keyHex
    ): void {
        $key = hex2bin($keyHex);
        $packet = self::rtcpPacket();

        $protected = $this->peer()->protectRtcp($name, $key, $packet);

        $this->assertSame(
            bin2hex($packet),
            bin2hex($this->session($profile, $key)->unprotectRtcp($protected)),
            "RTCP protected by the reference implementation under $name must decrypt back"
        );
    }

    /**
     * A tampered authentication tag has to be rejected rather than quietly decrypted.
     */
    #[DataProvider('profiles')]
    public function testRejectsATamperedPacket(SrtpProfile $profile, string $name, string $keyHex): void
    {
        $key = hex2bin($keyHex);
        $protected = $this->peer()->protect($name, $key, hex2bin(self::RTP));

        // Flip a bit in the final byte, which is inside the tag for every profile here.
        $last = \strlen($protected) - 1;
        $protected[$last] = \chr(\ord($protected[$last]) ^ 0x01);

        $this->expectException(SrtpException::class);
        $this->session($profile, $key)->unprotect($protected);
    }

    /**
     * Replaying a packet must be refused: without this a captured packet can be re-injected,
     * and RFC 3711 section 3.3.2 makes the replay list mandatory.
     */
    public function testRejectsAReplayedPacket(): void
    {
        $key = hex2bin(self::KEY_CM_128);
        $session = $this->session(SrtpProfile::AES128_CM_SHA1_80, $key);
        $protected = $this->peer()->protect('AES_CM_128_HMAC_SHA1_80', $key, hex2bin(self::RTP));

        $session->unprotect($protected);

        $this->expectException(SrtpException::class);
        $session->unprotect($protected);
    }

    private function session(SrtpProfile $profile, string $key): Session
    {
        return new Session(new Policy($profile, $key));
    }

    private function peer(): ReferencePeer
    {
        return $this->peer ??= ReferencePeer::create();
    }
}
