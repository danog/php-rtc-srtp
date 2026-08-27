<?php

namespace Tests\Webrtc\Srtp;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;
use ReflectionProperty;
use Webrtc\Srtp\Enum\SrtpProfile;
use Webrtc\Srtp\Enum\SsrcType;
use Webrtc\Srtp\Exception\SrtpException;
use Webrtc\Srtp\Exception\SrtpValidateException;
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

    #[DataProvider('profiles')]
    public function testAuthenticationFailureDoesNotPoisonReplayState(
        SrtpProfile $profile,
        string $_name,
        string $keyHex
    ): void {
        $key = hex2bin($keyHex);
        $sender = $this->session($profile, $key);
        $receiver = $this->session($profile, $key);
        $packet = self::rtpPacket(77, 'payload');
        $protected = $sender->protect($packet);
        $tampered = $protected;
        $tampered[\strlen($tampered) - 1] = \chr(\ord($tampered[\strlen($tampered) - 1]) ^ 1);

        try {
            $receiver->unprotect($tampered);
            $this->fail('A tampered SRTP packet was accepted.');
        } catch (SrtpException) {
        }

        $this->assertSame($packet, $receiver->unprotect($protected));
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

    public function testRfc3711KeyDerivationVector(): void
    {
        $derive = new ReflectionMethod(Session::class, 'derive');
        $masterKey = hex2bin('e1f97a0d3e018be0d64fa32c06de4139');
        $masterSalt = hex2bin('0ec675ad498afeebb6960b3aabe6');

        $this->assertSame(
            'c61e7a93744f39ee10734afe3ff7a087',
            bin2hex($derive->invoke(null, $masterKey, $masterSalt, 0, 16))
        );
        $this->assertSame(
            '30cbbc08863d8c85d49db34a9ae1',
            bin2hex($derive->invoke(null, $masterKey, $masterSalt, 2, 14))
        );
        $this->assertSame(
            'cebe321f6ff7716b6fd4ab49af256a156d38baa4',
            bin2hex($derive->invoke(null, $masterKey, $masterSalt, 1, 20))
        );
    }

    #[DataProvider('profiles')]
    public function testRolloverAndReorderingDoNotRegressState(
        SrtpProfile $profile,
        string $_name,
        string $keyHex
    ): void {
        $sender = $this->session($profile, hex2bin($keyHex));
        $receiver = $this->session($profile, hex2bin($keyHex));
        $first = self::rtpPacket(0xFFFE, 'first');
        $afterRollover = self::rtpPacket(0, 'second');
        $late = self::rtpPacket(0xFFFF, 'late');

        $this->assertSame($first, $receiver->unprotect($sender->protect($first)));
        $this->assertSame($afterRollover, $receiver->unprotect($sender->protect($afterRollover)));
        $this->assertSame($late, $receiver->unprotect($sender->protect($late)));

        $next = self::rtpPacket(1, 'third');
        $this->assertSame($next, $receiver->unprotect($sender->protect($next)));
    }

    public function testReplayWindowReallyCoversMoreThan64Packets(): void
    {
        $key = hex2bin(self::KEY_CM_128);
        $sender = $this->session(SrtpProfile::AES128_CM_SHA1_80, $key);
        $receiver = $this->session(SrtpProfile::AES128_CM_SHA1_80, $key);

        $old = $sender->protect(self::rtpPacket(1000, 'old'));
        $new = $sender->protect(self::rtpPacket(1100, 'new'));
        $late = $sender->protect(self::rtpPacket(1001, 'late'));
        $receiver->unprotect($old);
        $receiver->unprotect($new);
        $this->assertSame(self::rtpPacket(1001, 'late'), $receiver->unprotect($late));

        $this->expectException(SrtpException::class);
        $receiver->unprotect($late);
    }

    #[DataProvider('profiles')]
    public function testSrtcpReplayWindowAcceptsReordering(
        SrtpProfile $profile,
        string $_name,
        string $keyHex
    ): void {
        $sender = $this->session($profile, hex2bin($keyHex));
        $receiver = $this->session($profile, hex2bin($keyHex));
        $packet = self::rtcpPacket();
        $first = $sender->protectRtcp($packet);
        $second = $sender->protectRtcp($packet);
        $third = $sender->protectRtcp($packet);

        $this->assertSame($packet, $receiver->unprotectRtcp($first));
        $this->assertSame($packet, $receiver->unprotectRtcp($third));
        $this->assertSame($packet, $receiver->unprotectRtcp($second));

        $this->expectException(SrtpException::class);
        $receiver->unprotectRtcp($second);
    }

    #[DataProvider('profiles')]
    public function testRejectsTamperedSrtcp(SrtpProfile $profile, string $_name, string $keyHex): void
    {
        $sender = $this->session($profile, hex2bin($keyHex));
        $protected = $sender->protectRtcp(self::rtcpPacket());
        $protected[10] = \chr(\ord($protected[10]) ^ 1);

        $this->expectException(SrtpException::class);
        $this->session($profile, hex2bin($keyHex))->unprotectRtcp($protected);
    }

    #[DataProvider('profiles')]
    public function testDuplicateOutgoingIndexIsRejected(
        SrtpProfile $profile,
        string $_name,
        string $keyHex
    ): void {
        $session = $this->session($profile, hex2bin($keyHex));
        $packet = self::rtpPacket(42, 'payload');
        $session->protect($packet);

        $this->expectException(SrtpException::class);
        $session->protect($packet);
    }

    #[DataProvider('profiles')]
    public function testAllowedRetransmissionReturnsCachedCiphertextButRejectsChangedPlaintext(
        SrtpProfile $profile,
        string $_name,
        string $keyHex
    ): void {
        $policy = new Policy($profile, hex2bin($keyHex));
        $policy->setAllowRepeatTx(true);
        $session = new Session($policy);
        $packet = self::rtpPacket(42, 'payload');

        $this->assertSame($session->protect($packet), $session->protect($packet));

        $this->expectException(SrtpException::class);
        $session->protect(self::rtpPacket(42, 'changed'));
    }

    public function testSrtcpCounterExhaustionThrowsInsteadOfWrappingTheNonce(): void
    {
        $session = $this->session(SrtpProfile::AEAD_AES_128_GCM, hex2bin(self::KEY_GCM_128));
        (new ReflectionProperty(Session::class, 'rtcpKeyInvocations'))->setValue($session, 0x80000000);

        $this->expectException(SrtpException::class);
        $session->protectRtcp(self::rtcpPacket());
    }

    public function testSrtpKeyLifetimeExhaustionThrows(): void
    {
        $session = $this->session(SrtpProfile::AEAD_AES_128_GCM, hex2bin(self::KEY_GCM_128));
        (new ReflectionProperty(Session::class, 'rtpKeyInvocations'))->setValue($session, 0x1000000000000);

        $this->expectException(SrtpException::class);
        $session->protect(self::rtpPacket(1, 'payload'));
    }

    public function testSrtcpCanWrapOnlyAfterRekeying(): void
    {
        $oldKey = hex2bin(self::KEY_GCM_128);
        $newKey = random_bytes(28);
        $sender = $this->session(SrtpProfile::AEAD_AES_128_GCM, $oldKey);
        $ssrc = unpack('N', substr(self::rtcpPacket(), 4, 4))[1];
        (new ReflectionProperty(Session::class, 'rtcpIndex'))->setValue($sender, [$ssrc => 0x7FFFFFFF]);
        (new ReflectionProperty(Session::class, 'rtcpKeyUsage'))->setValue(
            $sender,
            [$ssrc => [
                'generation' => (new ReflectionProperty(Session::class, 'keyGeneration'))->getValue($sender),
                'invocations' => 0x80000000,
            ]]
        );

        $sender->addStream(new Policy(SrtpProfile::AEAD_AES_128_GCM, $newKey));
        $protected = $sender->protectRtcp(self::rtcpPacket());

        $this->assertSame('80000000', bin2hex(substr($protected, -4)));
        $this->assertSame(
            self::rtcpPacket(),
            $this->session(SrtpProfile::AEAD_AES_128_GCM, $newKey)->unprotectRtcp($protected)
        );
    }

    public function testReinstallingTheSameKeyDoesNotResetSrtcpUsageLimit(): void
    {
        $key = hex2bin(self::KEY_GCM_128);
        $policy = new Policy(SrtpProfile::AEAD_AES_128_GCM, $key);
        $session = new Session($policy);
        $ssrc = unpack('N', substr(self::rtcpPacket(), 4, 4))[1];
        (new ReflectionProperty(Session::class, 'rtcpKeyUsage'))->setValue(
            $session,
            [$ssrc => [
                'generation' => (new ReflectionProperty(Session::class, 'keyGeneration'))->getValue($session),
                'invocations' => 0x80000000,
            ]]
        );
        (new ReflectionProperty(Session::class, 'rtcpKeyInvocations'))->setValue($session, 0x80000000);
        $session->addStream($policy);

        $this->expectException(SrtpException::class);
        $session->protectRtcp(self::rtcpPacket());
    }

    public function testRtpRekeyPreservesRocButStartsFreshPerKeyReplayLists(): void
    {
        $oldKey = hex2bin(self::KEY_GCM_128);
        $newKey = random_bytes(28);
        $sender = $this->session(SrtpProfile::AEAD_AES_128_GCM, $oldKey);
        $receiver = $this->session(SrtpProfile::AEAD_AES_128_GCM, $oldKey);
        foreach ([0xFFFF, 0] as $sequence) {
            $packet = self::rtpPacket($sequence, 'old-key');
            $this->assertSame($packet, $receiver->unprotect($sender->protect($packet)));
        }

        $sender->addStream(new Policy(SrtpProfile::AEAD_AES_128_GCM, $newKey));
        $receiver->addStream(new Policy(SrtpProfile::AEAD_AES_128_GCM, $newKey));
        foreach ([0, 1] as $sequence) {
            $packet = self::rtpPacket($sequence, 'new-key');
            $this->assertSame($packet, $receiver->unprotect($sender->protect($packet)));
        }
    }

    public function testRfc7714AuthenticationOnlySrtcpVector(): void
    {
        $plain = hex2bin(
            '81c8000d4d6172734e5450314e545032525450200000042a0000e9304c756e61'
            .'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef'
        );
        $protected = hex2bin(
            '81c8000d4d6172734e5450314e545032525450200000042a0000e9304c756e61'
            .'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef'
            .'841dd9683dd78ec92ae58790125f62b3000005d4'
        );
        $session = $this->rfc7714RtcpSession();

        $this->assertSame($plain, $session->unprotectRtcp($protected));
    }

    public function testRfc7714EncryptedSrtcpVector(): void
    {
        $plain = hex2bin(
            '81c8000d4d6172734e5450314e545032525450200000042a0000e9304c756e61'
            .'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef'
        );
        $protected = hex2bin(
            '81c8000d4d61727363e94885dcdab67ca727d7662f6b7e99'
            .'7ff5c0f76c06f32dc676a5f1730d6fda4ce09b4686303ded0bb9275b'
            .'c84aa45896cf4d2fc5abf87245d9eade800005d4'
        );

        $this->assertSame($plain, $this->rfc7714RtcpSession()->unprotectRtcp($protected));
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function malformedPackets(): array
    {
        return [
            'short RTP' => ['protect', "\x80"],
            'wrong RTP version' => ['protect', "\x40".str_repeat("\0", 11)],
            'truncated CSRC list' => ['protect', "\x81".str_repeat("\0", 11)],
            'truncated RTP extension' => ['protect', "\x90".str_repeat("\0", 11)],
            'invalid RTP padding' => ['protect', "\xA0\0\0\1".str_repeat("\0", 8)."\0"],
            'short RTCP' => ['protectRtcp', "\x80\xC8"],
            'wrong RTCP version' => ['protectRtcp', "\x40\xC8\0\1".str_repeat("\0", 4)],
            'unaligned RTCP' => ['protectRtcp', "\x80\xC8\0\1".str_repeat("\0", 5)],
        ];
    }

    #[DataProvider('malformedPackets')]
    public function testMalformedPacketsAlwaysThrow(string $method, string $packet): void
    {
        $this->expectException(SrtpException::class);
        $this->session(SrtpProfile::AES128_CM_SHA1_80, hex2bin(self::KEY_CM_128))->{$method}($packet);
    }

    public function testRemovedOutboundSsrcCannotReuseNonceWithTheSameKey(): void
    {
        $session = $this->session(SrtpProfile::AEAD_AES_128_GCM, hex2bin(self::KEY_GCM_128));
        $packet = self::rtpPacket(1, 'payload');
        $session->protect($packet);
        $session->removeStream(0xCAFEBABE);

        $this->expectException(SrtpException::class);
        $session->protect(self::rtpPacket(2, 'payload'));
    }

    public function testRemovedInboundSsrcCannotReplayUnderTheSameKey(): void
    {
        $key = hex2bin(self::KEY_GCM_128);
        $sender = $this->session(SrtpProfile::AEAD_AES_128_GCM, $key);
        $receiver = $this->session(SrtpProfile::AEAD_AES_128_GCM, $key);
        $protected = $sender->protect(self::rtpPacket(1, 'payload'));
        $receiver->unprotect($protected);
        $receiver->removeStream(0xCAFEBABE);

        $this->expectException(SrtpException::class);
        $receiver->unprotect($protected);
    }

    public function testRemoveStreamRejectsInvalidSsrcInsteadOfCastingItToZero(): void
    {
        $this->expectException(SrtpValidateException::class);
        $this->session(SrtpProfile::AES128_CM_SHA1_80, hex2bin(self::KEY_CM_128))->removeStream('not-a-number');
    }

    public function testSpecificSsrcPolicyRejectsOtherStreams(): void
    {
        $policy = new Policy(
            SrtpProfile::AES128_CM_SHA1_80,
            hex2bin(self::KEY_CM_128),
            SsrcType::SPECIFIC,
            123
        );

        $this->expectException(SrtpException::class);
        (new Session($policy))->protect(self::rtpPacket(1, 'payload'));
    }

    public function testAesCmRejectsPacketsThatWouldExhaustThePerPacketCounter(): void
    {
        $this->expectException(SrtpException::class);
        $this->session(SrtpProfile::AES128_CM_SHA1_80, hex2bin(self::KEY_CM_128))->protect(
            self::rtpPacket(1, str_repeat('x', 0x100001))
        );
    }

    private static function rtpPacket(int $sequence, string $payload): string
    {
        return "\x80\x0f".pack('nN', $sequence, 0xDECAFBAD).pack('N', 0xCAFEBABE).$payload;
    }

    private function rfc7714RtcpSession(): Session
    {
        $session = $this->session(SrtpProfile::AEAD_AES_128_GCM, hex2bin(self::KEY_GCM_128));
        (new ReflectionProperty(Session::class, 'rtcpKey'))->setValue(
            $session,
            hex2bin('000102030405060708090a0b0c0d0e0f')
        );
        (new ReflectionProperty(Session::class, 'rtcpSalt'))->setValue(
            $session,
            hex2bin('517569642070726f2071756f')
        );
        return $session;
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
