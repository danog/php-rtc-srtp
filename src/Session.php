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
use Webrtc\Srtp\Exception\SrtpException;
use Webrtc\Srtp\Exception\SrtpValidateException;
use phpseclib3\Crypt\AES;
use Throwable;

/**
 * A pure-PHP SRTP/SRTCP session, implementing RFC 3711 (and RFC 7714 for the AEAD profiles).
 *
 * Upstream this class delegated to libsrtp through FFI. It is reimplemented here so that calls
 * work on a stock PHP installation: the only primitives needed are AES (from phpseclib3, which
 * transparently uses OpenSSL when the extension is available) and HMAC-SHA1 from ext-hash.
 *
 * A session protects one direction of one DTLS association. The same master key covers every SSRC
 * in that direction, so per-SSRC rollover counters and replay windows are tracked separately.
 */
class Session
{
    /** Label of the SRTP encryption key in the RFC 3711 key derivation function. */
    private const int LABEL_RTP_ENCRYPTION = 0x00;
    private const int LABEL_RTP_AUTH = 0x01;
    private const int LABEL_RTP_SALT = 0x02;
    private const int LABEL_RTCP_ENCRYPTION = 0x03;
    private const int LABEL_RTCP_AUTH = 0x04;
    private const int LABEL_RTCP_SALT = 0x05;

    /** Length of the HMAC-SHA1 session authentication key. */
    private const int AUTH_KEY_LENGTH = 20;

    /** Sequence numbers are 16 bit, so a rollover happens every 65536 packets. */
    private const int SEQ_MODULO = 0x10000;

    private ?Policy $policy = null;

    private SrtpProfile $profile;
    private bool $aead = false;
    private int $rtpTagLength = 10;
    private int $rtcpTagLength = 10;

    private string $rtpKey = '';
    private string $rtpSalt = '';
    private string $rtpAuthKey = '';
    private string $rtcpKey = '';
    private string $rtcpSalt = '';
    private string $rtcpAuthKey = '';

    /**
     * Per-SSRC RTP state: rollover counter, highest seen sequence number and replay bitmap.
     *
     * @var array<int, array{roc: int, highestSeq: int, replay: int, seen: bool}>
     */
    private array $rtpState = [];

    /**
     * Per-SSRC SRTCP index, used for the outgoing direction.
     *
     * @var array<int, int>
     */
    private array $rtcpIndex = [];

    /**
     * Highest SRTCP index seen per SSRC, used for replay protection on the incoming direction.
     *
     * @var array<int, int>
     */
    private array $rtcpHighestIndex = [];

    /**
     * @throws SrtpValidateException If the policy is not usable.
     */
    public function __construct(?Policy $policy = null)
    {
        if ($policy !== null) {
            $this->addStream($policy);
        }
    }

    /**
     * Install (or replace) the cryptographic policy of this session.
     *
     * @throws SrtpValidateException If no key was set on the policy.
     */
    public function addStream(Policy $policy): void
    {
        if ($policy->getKey() === null) {
            throw new SrtpValidateException('The SRTP policy has no key!');
        }
        $this->policy = $policy;
        $this->profile = $policy->getSrtpProfile();
        $this->aead = Policy::isAead($this->profile);
        $this->rtpTagLength = Policy::rtpTagLength($this->profile);
        $this->rtcpTagLength = Policy::rtcpTagLength($this->profile);

        $masterKey = $policy->getMasterKey();
        $masterSalt = $policy->getMasterSalt();
        $keyLength = \strlen($masterKey);
        $saltLength = \strlen($masterSalt);

        $this->rtpKey = self::derive($masterKey, $masterSalt, self::LABEL_RTP_ENCRYPTION, $keyLength);
        $this->rtpSalt = self::derive($masterKey, $masterSalt, self::LABEL_RTP_SALT, $saltLength);
        $this->rtcpKey = self::derive($masterKey, $masterSalt, self::LABEL_RTCP_ENCRYPTION, $keyLength);
        $this->rtcpSalt = self::derive($masterKey, $masterSalt, self::LABEL_RTCP_SALT, $saltLength);
        if (!$this->aead) {
            $this->rtpAuthKey = self::derive($masterKey, $masterSalt, self::LABEL_RTP_AUTH, self::AUTH_KEY_LENGTH);
            $this->rtcpAuthKey = self::derive($masterKey, $masterSalt, self::LABEL_RTCP_AUTH, self::AUTH_KEY_LENGTH);
        }
    }

    /**
     * Forget the state associated with an SSRC.
     */
    public function removeStream(int|string $ssrc): void
    {
        $ssrc = (int) $ssrc;
        unset($this->rtpState[$ssrc], $this->rtcpIndex[$ssrc], $this->rtcpHighestIndex[$ssrc]);
    }

    /**
     * RFC 3711 key derivation function: AES in counter mode, keyed with the master key.
     */
    private static function derive(string $masterKey, string $masterSalt, int $label, int $length): string
    {
        // x = key_id XOR master_salt, with key_id = label || (index / kdr), kdr being 0 here.
        $x = $masterSalt;
        $offset = \strlen($x) - 7;
        $x[$offset] = \chr(\ord($x[$offset]) ^ $label);

        return self::keystream($masterKey, str_pad($x, 16, "\0"), $length);
    }

    /**
     * Produce `$length` bytes of AES counter-mode keystream.
     */
    private static function keystream(string $key, string $iv, int $length): string
    {
        if ($length === 0) {
            return '';
        }
        $aes = new AES('ctr');
        $aes->setKey($key);
        $aes->setIV($iv);
        $aes->disablePadding();
        return substr($aes->encrypt(str_repeat("\0", $length)), 0, $length);
    }

    /**
     * Build the AES counter-mode IV of RFC 3711 §4.1.1.
     */
    private static function iv(string $salt, int $ssrc, int $index): string
    {
        $iv = str_pad($salt, 16, "\0");
        // XOR the SSRC in at bytes 4..7 and the 48-bit packet index at bytes 8..13.
        $mix = str_repeat("\0", 4).pack('N', $ssrc & 0xFFFFFFFF)
            .pack('N', ($index >> 16) & 0xFFFFFFFF).pack('n', $index & 0xFFFF).\chr(0).\chr(0);
        return $iv ^ $mix;
    }

    /**
     * Build the AEAD nonce of RFC 7714 §8.1: the 12 byte salt XORed with the SSRC and index.
     */
    private static function aeadNonce(string $salt, int $ssrc, int $index): string
    {
        $mix = str_repeat("\0", 2).pack('N', $ssrc & 0xFFFFFFFF)
            .pack('N', ($index >> 16) & 0xFFFFFFFF).pack('n', $index & 0xFFFF);
        return $salt ^ $mix;
    }

    /**
     * Length of the RTP header of a packet, including CSRCs and the header extension.
     *
     * @throws SrtpException If the packet is malformed.
     */
    private static function rtpHeaderLength(string $packet): int
    {
        if (\strlen($packet) < 12) {
            throw new SrtpException('RTP packet is too short!');
        }
        $first = \ord($packet[0]);
        if (($first >> 6) !== 2) {
            throw new SrtpException('Unsupported RTP version!');
        }
        $length = 12 + 4 * ($first & 0x0F);
        if ($first & 0x10) {
            // A header extension follows the CSRC list: 2 bytes of profile, 2 bytes of length.
            if (\strlen($packet) < $length + 4) {
                throw new SrtpException('Truncated RTP header extension!');
            }
            $words = unpack('n', substr($packet, $length + 2, 2))[1];
            $length += 4 + 4 * $words;
        }
        if (\strlen($packet) < $length) {
            throw new SrtpException('Truncated RTP header!');
        }
        return $length;
    }

    /**
     * Encrypt and authenticate an outgoing RTP packet.
     *
     * @throws SrtpException If the packet cannot be protected.
     */
    public function protect(string $packet): string
    {
        $this->assertReady();
        $headerLength = self::rtpHeaderLength($packet);
        $header = substr($packet, 0, $headerLength);
        $payload = substr($packet, $headerLength);

        $unpacked = unpack('nseq/Nts/Nssrc', substr($packet, 2, 10));
        $seq = $unpacked['seq'];
        $ssrc = $unpacked['ssrc'];

        $roc = $this->nextOutgoingRoc($ssrc, $seq);
        $index = ($roc * self::SEQ_MODULO) + $seq;

        if ($this->aead) {
            $aes = new AES('gcm');
            $aes->setKey($this->rtpKey);
            $aes->setNonce(self::aeadNonce($this->rtpSalt, $ssrc, $index));
            $aes->setAAD($header);
            return $header.$aes->encrypt($payload).$aes->getTag();
        }

        $encrypted = $payload === ''
            ? ''
            : $payload ^ self::keystream($this->rtpKey, self::iv($this->rtpSalt, $ssrc, $index), \strlen($payload));

        $authenticated = $header.$encrypted;
        $tag = substr(
            hash_hmac('sha1', $authenticated.pack('N', $roc), $this->rtpAuthKey, true),
            0,
            $this->rtpTagLength
        );

        return $authenticated.$tag;
    }

    /**
     * Authenticate and decrypt an incoming RTP packet.
     *
     * @throws SrtpException If authentication fails or the packet is malformed.
     */
    public function unprotect(string $packet): string
    {
        $this->assertReady();
        if (\strlen($packet) < 12 + $this->rtpTagLength) {
            throw new SrtpException('SRTP packet is too short!');
        }
        $unpacked = unpack('nseq/Nts/Nssrc', substr($packet, 2, 10));
        $seq = $unpacked['seq'];
        $ssrc = $unpacked['ssrc'];

        $roc = $this->estimateRoc($ssrc, $seq);
        $index = ($roc * self::SEQ_MODULO) + $seq;
        $this->checkReplay($ssrc, $index);

        $headerLength = self::rtpHeaderLength($packet);
        $header = substr($packet, 0, $headerLength);

        if ($this->aead) {
            $body = substr($packet, $headerLength, -$this->rtpTagLength);
            $tag = substr($packet, -$this->rtpTagLength);
            $aes = new AES('gcm');
            $aes->setKey($this->rtpKey);
            $aes->setNonce(self::aeadNonce($this->rtpSalt, $ssrc, $index));
            $aes->setAAD($header);
            $aes->setTag($tag);
            try {
                $plain = $aes->decrypt($body);
            } catch (Throwable $e) {
                // phpseclib signals a tag mismatch by throwing, not by returning false.
                throw new SrtpException('SRTP authentication failed!', 0, $e);
            }
            $this->acceptReplay($ssrc, $index, $seq, $roc);
            return $header.$plain;
        }

        $authenticated = substr($packet, 0, -$this->rtpTagLength);
        $tag = substr($packet, -$this->rtpTagLength);
        $expected = substr(
            hash_hmac('sha1', $authenticated.pack('N', $roc), $this->rtpAuthKey, true),
            0,
            $this->rtpTagLength
        );
        if (!hash_equals($expected, $tag)) {
            throw new SrtpException('SRTP authentication failed!');
        }

        $encrypted = substr($authenticated, $headerLength);
        $payload = $encrypted === ''
            ? ''
            : $encrypted ^ self::keystream($this->rtpKey, self::iv($this->rtpSalt, $ssrc, $index), \strlen($encrypted));

        $this->acceptReplay($ssrc, $index, $seq, $roc);
        return $header.$payload;
    }

    /**
     * Encrypt and authenticate an outgoing RTCP packet.
     *
     * @throws SrtpException If the packet cannot be protected.
     */
    public function protectRtcp(string $packet): string
    {
        $this->assertReady();
        if (\strlen($packet) < 8) {
            throw new SrtpException('RTCP packet is too short!');
        }
        $header = substr($packet, 0, 8);
        $payload = substr($packet, 8);
        $ssrc = unpack('N', substr($packet, 4, 4))[1];

        $index = ($this->rtcpIndex[$ssrc] ?? 0) + 1;
        if ($index > 0x7FFFFFFF) {
            $index = 1;
        }
        $this->rtcpIndex[$ssrc] = $index;
        // The most significant bit of the trailing word flags the packet as encrypted.
        $indexWord = pack('N', $index | 0x80000000);

        if ($this->aead) {
            $aes = new AES('gcm');
            $aes->setKey($this->rtcpKey);
            $aes->setNonce(self::aeadNonce($this->rtcpSalt, $ssrc, $index));
            $aes->setAAD($header.$indexWord);
            return $header.$aes->encrypt($payload).$aes->getTag().$indexWord;
        }

        $encrypted = $payload === ''
            ? ''
            : $payload ^ self::keystream($this->rtcpKey, self::iv($this->rtcpSalt, $ssrc, $index), \strlen($payload));

        $authenticated = $header.$encrypted.$indexWord;
        $tag = substr(hash_hmac('sha1', $authenticated, $this->rtcpAuthKey, true), 0, $this->rtcpTagLength);

        return $authenticated.$tag;
    }

    /**
     * Authenticate and decrypt an incoming RTCP packet.
     *
     * @throws SrtpException If authentication fails or the packet is malformed.
     */
    public function unprotectRtcp(string $packet): string
    {
        $this->assertReady();
        $minimum = 8 + 4 + $this->rtcpTagLength;
        if (\strlen($packet) < $minimum) {
            throw new SrtpException('SRTCP packet is too short!');
        }
        $header = substr($packet, 0, 8);
        $ssrc = unpack('N', substr($packet, 4, 4))[1];

        if ($this->aead) {
            $indexWord = substr($packet, -4);
            $body = substr($packet, 8, -(4 + $this->rtcpTagLength));
            $tag = substr($packet, -(4 + $this->rtcpTagLength), $this->rtcpTagLength);
        } else {
            $tag = substr($packet, -$this->rtcpTagLength);
            $authenticated = substr($packet, 0, -$this->rtcpTagLength);
            $expected = substr(hash_hmac('sha1', $authenticated, $this->rtcpAuthKey, true), 0, $this->rtcpTagLength);
            if (!hash_equals($expected, $tag)) {
                throw new SrtpException('SRTCP authentication failed!');
            }
            $indexWord = substr($authenticated, -4);
            $body = substr($authenticated, 8, -4);
        }

        $rawIndex = unpack('N', $indexWord)[1];
        $encryptedFlag = ($rawIndex & 0x80000000) !== 0;
        $index = $rawIndex & 0x7FFFFFFF;

        if (($this->rtcpHighestIndex[$ssrc] ?? -1) >= $index) {
            throw new SrtpException('Replayed SRTCP packet!');
        }

        if ($this->aead) {
            $aes = new AES('gcm');
            $aes->setKey($this->rtcpKey);
            $aes->setNonce(self::aeadNonce($this->rtcpSalt, $ssrc, $index));
            $aes->setAAD($header.$indexWord);
            $aes->setTag($tag);
            try {
                $plain = $aes->decrypt($body);
            } catch (Throwable $e) {
                throw new SrtpException('SRTCP authentication failed!', 0, $e);
            }
            $this->rtcpHighestIndex[$ssrc] = $index;
            return $header.$plain;
        }

        $payload = !$encryptedFlag || $body === ''
            ? $body
            : $body ^ self::keystream($this->rtcpKey, self::iv($this->rtcpSalt, $ssrc, $index), \strlen($body));

        $this->rtcpHighestIndex[$ssrc] = $index;
        return $header.$payload;
    }

    /**
     * Track the rollover counter of an outgoing stream.
     */
    private function nextOutgoingRoc(int $ssrc, int $seq): int
    {
        if (!isset($this->rtpState[$ssrc])) {
            $this->rtpState[$ssrc] = ['roc' => 0, 'highestSeq' => $seq, 'replay' => 0, 'seen' => true];
            return 0;
        }
        $state = &$this->rtpState[$ssrc];
        if ($seq < $state['highestSeq'] && $state['highestSeq'] - $seq > self::SEQ_MODULO / 2) {
            $state['roc']++;
        }
        $state['highestSeq'] = $seq;
        return $state['roc'];
    }

    /**
     * Guess the rollover counter of an incoming packet, per RFC 3711 Appendix A.
     */
    private function estimateRoc(int $ssrc, int $seq): int
    {
        if (!isset($this->rtpState[$ssrc])) {
            return 0;
        }
        $state = $this->rtpState[$ssrc];
        $roc = $state['roc'];
        $highest = $state['highestSeq'];
        $half = self::SEQ_MODULO / 2;

        if ($highest < $half) {
            if ($seq - $highest > $half) {
                return $roc > 0 ? $roc - 1 : 0;
            }
            return $roc;
        }
        if ($highest - $half > $seq) {
            return $roc + 1;
        }
        return $roc;
    }

    /**
     * Reject packets that were already processed.
     *
     * @throws SrtpException If the packet is a replay or too old.
     */
    private function checkReplay(int $ssrc, int $index): void
    {
        $state = $this->rtpState[$ssrc] ?? null;
        if ($state === null || !$state['seen']) {
            return;
        }
        $highest = ($state['roc'] * self::SEQ_MODULO) + $state['highestSeq'];
        $delta = $highest - $index;
        if ($delta < 0) {
            return;
        }
        $window = $this->policy?->getWindowSize() ?? 1024;
        // The bitmap only covers 64 packets; anything older is simply refused.
        if ($delta >= min($window, 64)) {
            throw new SrtpException('SRTP packet is too old!');
        }
        if (($state['replay'] >> $delta) & 1) {
            throw new SrtpException('Replayed SRTP packet!');
        }
    }

    /**
     * Record a successfully authenticated packet in the replay window.
     */
    private function acceptReplay(int $ssrc, int $index, int $seq, int $roc): void
    {
        if (!isset($this->rtpState[$ssrc])) {
            $this->rtpState[$ssrc] = ['roc' => $roc, 'highestSeq' => $seq, 'replay' => 1, 'seen' => true];
            return;
        }
        $state = &$this->rtpState[$ssrc];
        $highest = ($state['roc'] * self::SEQ_MODULO) + $state['highestSeq'];
        if ($index > $highest) {
            $shift = $index - $highest;
            $state['replay'] = $shift >= 64 ? 1 : (($state['replay'] << $shift) | 1) & PHP_INT_MAX;
            $state['roc'] = $roc;
            $state['highestSeq'] = $seq;
        } else {
            $state['replay'] |= 1 << ($highest - $index);
        }
        $state['seen'] = true;
    }

    /**
     * @throws SrtpException If no key was installed yet.
     */
    private function assertReady(): void
    {
        if ($this->policy === null) {
            throw new SrtpException('The SRTP session has no key!');
        }
    }
}
