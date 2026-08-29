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

use phpseclib3\Crypt\AES;
use Throwable;
use Webrtc\Srtp\Enum\SsrcType;
use Webrtc\Srtp\Exception\SrtpException;
use Webrtc\Srtp\Exception\SrtpValidateException;

/** A pure-PHP SRTP/SRTCP session implementing RFC 3711 and RFC 7714. */
final class Session
{
    private const LABEL_RTP_ENCRYPTION = 0x00;
    private const LABEL_RTP_AUTH = 0x01;
    private const LABEL_RTP_SALT = 0x02;
    private const LABEL_RTCP_ENCRYPTION = 0x03;
    private const LABEL_RTCP_AUTH = 0x04;
    private const LABEL_RTCP_SALT = 0x05;
    private const AUTH_KEY_LENGTH = 20;
    private const SEQ_MODULO = 0x10000;
    private const SEQ_MEDIAN = 0x8000;
    private const MAX_ROC = 0xFFFFFFFF;
    private const MAX_SRTCP_INDEX = 0x7FFFFFFF;
    private const MAX_SRTP_INVOCATIONS = 0x1000000000000;
    private const MAX_SRTCP_INVOCATIONS = 0x80000000;
    private const MAX_AES_CM_BYTES = 0x100000;
    private const MAX_GCM_PLAINTEXT_BYTES = 0xFFFFFFFE0;

    private bool $ready = false;
    private bool $aead = false;
    private bool $allowRepeatTx = false;
    private int $windowSize = 1024;
    private int $rtpTagLength = 10;
    private int $rtcpTagLength = 10;
    private int $keyGeneration = 0;
    private int $rtpKeyInvocations = 0;
    private int $rtcpKeyInvocations = 0;
    private SsrcType $ssrcType = SsrcType::UNDEFINED;
    private int $ssrcValue = 0;

    private string $rtpKey = '';
    private string $rtpSalt = '';
    private string $rtpAuthKey = '';
    private string $rtcpKey = '';
    private string $rtcpSalt = '';
    private string $rtcpAuthKey = '';

    /**
     * @var array<int, array{
     *     highestIndex: int,
     *     sent: array<int, array{packet: string, protected: ?string, generation: int}>
     * }>
     */
    private array $rtpSendState = [];

    /** @var array<int, array{highestIndex: int, received: array<int, true>}> */
    private array $rtpReceiveState = [];

    /** @var array<int, int> Last outgoing SRTCP index for each SSRC. */
    private array $rtcpIndex = [];

    /** @var array<int, array{generation: int, invocations: int}> */
    private array $rtcpKeyUsage = [];

    /** @var array<int, array{highestIndex: int, received: array<int, true>}> */
    private array $rtcpReceiveState = [];

    /** @var array<int, true> SSRCs removed while the current master key was active. */
    private array $retiredSsrc = [];

    private ?string $masterKeyId = null;

    /** @throws SrtpValidateException If the policy is not usable. */
    public function __construct(?Policy $policy = null)
    {
        if (PHP_INT_SIZE < 8) {
            throw new SrtpValidateException('SRTP requires a 64-bit PHP build for 48-bit packet indices.');
        }
        if ($policy !== null) {
            $this->addStream($policy);
        }
    }

    /**
     * Install or re-key the cryptographic context.
     *
     * Packet indices deliberately survive a re-key, as required by RFC 3711 section 3.3.1.
     * Derived material is computed before the live context is changed, so a primitive failure
     * cannot leave a half-installed policy behind.
     *
     * @throws SrtpValidateException If the policy is unusable or key derivation fails.
     */
    public function addStream(Policy $policy): void
    {
        $material = $policy->getKey();
        if ($material === null) {
            throw new SrtpValidateException('The SRTP policy has no key!');
        }

        try {
            $profile = $policy->getSrtpProfile();
            $aead = Policy::isAead($profile);
            $rtpTagLength = Policy::rtpTagLength($profile);
            $rtcpTagLength = Policy::rtcpTagLength($profile);
            $masterKey = $policy->getMasterKey();
            $masterSalt = $policy->getMasterSalt();
            $keyLength = \strlen($masterKey);
            $saltLength = \strlen($masterSalt);

            $rtpKey = self::derive($masterKey, $masterSalt, self::LABEL_RTP_ENCRYPTION, $keyLength);
            $rtpSalt = self::derive($masterKey, $masterSalt, self::LABEL_RTP_SALT, $saltLength);
            $rtcpKey = self::derive($masterKey, $masterSalt, self::LABEL_RTCP_ENCRYPTION, $keyLength);
            $rtcpSalt = self::derive($masterKey, $masterSalt, self::LABEL_RTCP_SALT, $saltLength);
            $rtpAuthKey = $aead
                ? ''
                : self::derive($masterKey, $masterSalt, self::LABEL_RTP_AUTH, self::AUTH_KEY_LENGTH);
            $rtcpAuthKey = $aead
                ? ''
                : self::derive($masterKey, $masterSalt, self::LABEL_RTCP_AUTH, self::AUTH_KEY_LENGTH);
            $keyId = hash('sha256', $profile->value."\0".$material, true);
            if (\strlen($keyId) !== 32) {
                throw new SrtpValidateException('Could not identify the installed SRTP master key.');
            }
        } catch (SrtpValidateException $e) {
            throw $e;
        } catch (Throwable $e) {
            throw new SrtpValidateException('Could not derive the SRTP session keys.', 0, $e);
        }

        $keyChanged = $this->masterKeyId === null || !hash_equals($this->masterKeyId, $keyId);
        if ($this->masterKeyId !== null && $keyChanged) {
            // A new master key starts a new SSRC-allocation lifetime. Packet indices remain.
            $this->retiredSsrc = [];
            foreach ($this->rtpSendState as &$state) {
                $state['sent'] = [];
            }
            unset($state);
            foreach ($this->rtpReceiveState as &$state) {
                $state['received'] = [];
            }
            unset($state);
            // Old SRTCP packets cannot authenticate under the new key. Starting a fresh replay
            // list also permits the explicit 31-bit index to wrap safely after a re-key.
            $this->rtcpReceiveState = [];
        }
        if ($keyChanged) {
            $this->rtpKeyInvocations = 0;
            $this->rtcpKeyInvocations = 0;
        }

        $this->aead = $aead;
        $this->allowRepeatTx = $policy->getAllowRepeatTx();
        $this->windowSize = $policy->getWindowSize();
        $this->rtpTagLength = $rtpTagLength;
        $this->rtcpTagLength = $rtcpTagLength;
        $this->rtpKey = $rtpKey;
        $this->rtpSalt = $rtpSalt;
        $this->rtpAuthKey = $rtpAuthKey;
        $this->rtcpKey = $rtcpKey;
        $this->rtcpSalt = $rtcpSalt;
        $this->rtcpAuthKey = $rtcpAuthKey;
        $this->ssrcType = $policy->getSsrcType();
        $this->ssrcValue = $policy->getSsrcValue();
        $this->masterKeyId = $keyId;
        if ($keyChanged) {
            $this->keyGeneration++;
        }
        $this->ready = true;
    }

    /**
     * Retire an SSRC and forget its inbound replay state.
     *
     * Outbound indices are retained to prevent AES-CTR keystream or AES-GCM nonce reuse. The SSRC
     * cannot be accepted or issued again until a new master key is installed.
     *
     * @throws SrtpValidateException If the SSRC is not an unsigned 32-bit integer.
     */
    public function removeStream(int|string $ssrc): void
    {
        $ssrc = self::normalizeSsrc($ssrc);
        unset($this->rtpReceiveState[$ssrc], $this->rtcpReceiveState[$ssrc]);
        // Re-issuing an SSRC under the same key can repeat an RTP/SRTCP nonce. Retiring even an
        // as-yet unseen SSRC also makes an administrative removal effective against later input.
        $this->retiredSsrc[$ssrc] = true;
    }

    /** RFC 3711 AES-CM PRF with key_derivation_rate equal to zero. */
    private static function derive(string $masterKey, string $masterSalt, int $label, int $length): string
    {
        $x = str_pad($masterSalt, 16, "\0");
        $x[7] = \chr(\ord($x[7]) ^ $label);
        return self::keystream($masterKey, $x, $length);
    }

    /** Produce AES counter-mode keystream. */
    private static function keystream(string $key, string $iv, int $length): string
    {
        if ($length > self::MAX_AES_CM_BYTES) {
            throw new SrtpException('AES-CM cannot safely process more than 2^16 blocks per packet.');
        }
        if ($length === 0) {
            return '';
        }
        $aes = new AES('ctr');
        $aes->setKey($key);
        $aes->setIV($iv);
        $aes->disablePadding();
        $result = $aes->encrypt(str_repeat("\0", $length));
        if (\strlen($result) < $length) {
            throw new SrtpException('AES-CTR returned a truncated keystream.');
        }
        return substr($result, 0, $length);
    }

    /** RFC 3711 section 4.1.1 AES-CM IV. */
    private static function iv(string $salt, int $ssrc, int $index): string
    {
        $mix = str_repeat("\0", 4).pack('N', $ssrc)
            .pack('N', ($index >> 16) & 0xFFFFFFFF).pack('n', $index & 0xFFFF)."\0\0";
        return str_pad($salt, 16, "\0") ^ $mix;
    }

    /** RFC 7714 SRTP/SRTCP nonce. A 31-bit SRTCP index has two leading zero octets. */
    private static function aeadNonce(string $salt, int $ssrc, int $index): string
    {
        $mix = "\0\0".pack('N', $ssrc)
            .pack('N', ($index >> 16) & 0xFFFFFFFF).pack('n', $index & 0xFFFF);
        return $salt ^ $mix;
    }

    /** @throws SrtpException If the packet has an invalid or truncated RTP header. */
    private static function rtpHeaderLength(string $packet, int $trailerLength = 0): int
    {
        $packetLength = \strlen($packet) - $trailerLength;
        if ($packetLength < 12) {
            throw new SrtpException('RTP packet is too short!');
        }
        $first = \ord($packet[0]);
        if (($first >> 6) !== 2) {
            throw new SrtpException('Unsupported RTP version!');
        }
        $length = 12 + 4 * ($first & 0x0F);
        if ($length > $packetLength) {
            throw new SrtpException('Truncated RTP header!');
        }
        if (($first & 0x10) !== 0) {
            if ($length + 4 > $packetLength) {
                throw new SrtpException('Truncated RTP header extension!');
            }
            $words = unpack('nlength', substr($packet, $length + 2, 2));
            if ($words === false) {
                throw new SrtpException('Could not parse the RTP header extension!');
            }
            $length += 4 + 4 * (int) $words['length'];
            if ($length > $packetLength) {
                throw new SrtpException('Truncated RTP header extension!');
            }
        }
        return $length;
    }

    /** @throws SrtpException If RTP padding is malformed. */
    private static function validateRtpPadding(string $packet, int $headerLength): void
    {
        if ((\ord($packet[0]) & 0x20) === 0) {
            return;
        }
        $payloadLength = \strlen($packet) - $headerLength;
        if ($payloadLength === 0) {
            throw new SrtpException('RTP padding flag is set on an empty payload!');
        }
        $paddingLength = \ord($packet[\strlen($packet) - 1]);
        if ($paddingLength === 0 || $paddingLength > $payloadLength) {
            throw new SrtpException('Invalid RTP padding length!');
        }
    }

    /** @throws SrtpException If the packet cannot be a valid RTCP packet. */
    private static function validateRtcpEnvelope(string $packet, int $plainLength): void
    {
        if ($plainLength < 8 || $plainLength > \strlen($packet)) {
            throw new SrtpException('RTCP packet is too short!');
        }
        if ($plainLength % 4 !== 0) {
            throw new SrtpException('RTCP packet is not 32-bit aligned!');
        }
        if ((\ord($packet[0]) >> 6) !== 2) {
            throw new SrtpException('Unsupported RTCP version!');
        }
    }

    /**
     * Validate the part of RTCP framing needed by SRTCP itself.
     *
     * The RTCP length describes only the first member of a compound packet and is deliberately
     * not used to locate the SRTCP trailer (RFC 3711 section 3.4). Full RTCP semantic validation
     * belongs to the RTCP parser after cryptographic processing.
     */
    private static function validateRtcpPacket(string $packet): void
    {
        self::validateRtcpEnvelope($packet, \strlen($packet));
    }

    /** @throws SrtpException If the packet cannot be protected. */
    public function protect(string $packet): string
    {
        $this->assertReady();
        try {
            $headerLength = self::rtpHeaderLength($packet);
            self::validateRtpPadding($packet, $headerLength);
            $fields = self::rtpFields($packet);
            $ssrc = $fields['ssrc'];
            $this->assertSsrcAllowed($ssrc);

            [$roc, $index, $cached] = $this->reserveOutgoingRtp($ssrc, $fields['seq'], $packet);
            if ($cached !== null) {
                return $cached;
            }

            $header = substr($packet, 0, $headerLength);
            $payload = substr($packet, $headerLength);
            if ($this->aead) {
                $result = $header.$this->encryptGcm(
                    $this->rtpKey,
                    self::aeadNonce($this->rtpSalt, $ssrc, $index),
                    $header,
                    $payload,
                    'SRTP'
                );
            } else {
                $encrypted = $payload === ''
                    ? ''
                    : $payload ^ self::keystream(
                        $this->rtpKey,
                        self::iv($this->rtpSalt, $ssrc, $index),
                        \strlen($payload)
                    );
                $authenticated = $header.$encrypted;
                $tag = substr(self::hmacSha1(
                    $authenticated.pack('N', $roc),
                    $this->rtpAuthKey
                ), 0, $this->rtpTagLength);
                $result = $authenticated.$tag;
            }
            $this->commitOutgoingRtp($ssrc, $index, $result);
            return $result;
        } catch (SrtpException $e) {
            throw $e;
        } catch (Throwable $e) {
            throw new SrtpException('Could not protect the RTP packet.', 0, $e);
        }
    }

    /** @throws SrtpException If authentication fails or the packet is malformed/replayed. */
    public function unprotect(string $packet): string
    {
        $this->assertReady();
        try {
            $headerLength = self::rtpHeaderLength($packet, $this->rtpTagLength);
            $fields = self::rtpFields($packet);
            $this->assertSsrcAllowed($fields['ssrc']);
            [$roc, $index] = $this->estimateIncomingRtp($fields['ssrc'], $fields['seq']);
            $this->checkReplay($this->rtpReceiveState[$fields['ssrc']] ?? null, $index, 'SRTP');

            $header = substr($packet, 0, $headerLength);
            if ($this->aead) {
                $body = substr($packet, $headerLength, -$this->rtpTagLength);
                $tag = substr($packet, -$this->rtpTagLength);
                $payload = $this->decryptGcm(
                    $this->rtpKey,
                    self::aeadNonce($this->rtpSalt, $fields['ssrc'], $index),
                    $header,
                    $body,
                    $tag,
                    'SRTP'
                );
            } else {
                $authenticated = substr($packet, 0, -$this->rtpTagLength);
                $tag = substr($packet, -$this->rtpTagLength);
                $expected = substr(self::hmacSha1(
                    $authenticated.pack('N', $roc),
                    $this->rtpAuthKey
                ), 0, $this->rtpTagLength);
                if (!hash_equals($expected, $tag)) {
                    throw new SrtpException('SRTP authentication failed!');
                }
                $encrypted = substr($authenticated, $headerLength);
                $payload = $encrypted === ''
                    ? ''
                    : $encrypted ^ self::keystream(
                        $this->rtpKey,
                        self::iv($this->rtpSalt, $fields['ssrc'], $index),
                        \strlen($encrypted)
                    );
            }

            $plain = $header.$payload;
            self::validateRtpPadding($plain, $headerLength);
            $this->acceptReplay($this->rtpReceiveState, $fields['ssrc'], $index);
            return $plain;
        } catch (SrtpException $e) {
            throw $e;
        } catch (Throwable $e) {
            throw new SrtpException('Could not unprotect the SRTP packet.', 0, $e);
        }
    }

    /** @throws SrtpException If the packet cannot be protected. */
    public function protectRtcp(string $packet): string
    {
        $this->assertReady();
        try {
            self::validateRtcpPacket($packet);
            $ssrc = self::rtcpSsrc($packet);
            $this->assertSsrcAllowed($ssrc);
            if ($this->rtcpKeyInvocations >= self::MAX_SRTCP_INVOCATIONS) {
                throw new SrtpException('The SRTCP packet limit for this key has been reached; re-keying is required.');
            }
            // Consume the invocation before touching the primitive so a failed operation cannot
            // be retried in a way that accidentally reuses partially consumed cryptographic state.
            $this->rtcpKeyInvocations++;
            $usage = $this->rtcpKeyUsage[$ssrc] ?? null;
            if ($usage === null || $usage['generation'] !== $this->keyGeneration) {
                $usage = ['generation' => $this->keyGeneration, 'invocations' => 0];
            }
            if ($usage['invocations'] >= self::MAX_SRTCP_INDEX + 1) {
                throw new SrtpException('The SRTCP packet limit for this key has been reached; re-keying is required.');
            }
            $previous = $this->rtcpIndex[$ssrc] ?? 0;
            // libSRTP and pion start at one. The explicit index is modulo 2^31, while the
            // per-key invocation counter prevents any nonce from recurring under one key.
            $index = ($previous + 1) & self::MAX_SRTCP_INDEX;
            $this->rtcpIndex[$ssrc] = $index;
            $usage['invocations']++;
            $this->rtcpKeyUsage[$ssrc] = $usage;
            $indexWord = pack('N', $index | 0x80000000);
            $header = substr($packet, 0, 8);
            $payload = substr($packet, 8);

            if ($this->aead) {
                return $header.$this->encryptGcm(
                    $this->rtcpKey,
                    self::aeadNonce($this->rtcpSalt, $ssrc, $index),
                    $header.$indexWord,
                    $payload,
                    'SRTCP'
                ).$indexWord;
            }

            $encrypted = $payload === ''
                ? ''
                : $payload ^ self::keystream(
                    $this->rtcpKey,
                    self::iv($this->rtcpSalt, $ssrc, $index),
                    \strlen($payload)
                );
            $authenticated = $header.$encrypted.$indexWord;
            $tag = substr(self::hmacSha1($authenticated, $this->rtcpAuthKey), 0, $this->rtcpTagLength);
            return $authenticated.$tag;
        } catch (SrtpException $e) {
            throw $e;
        } catch (Throwable $e) {
            throw new SrtpException('Could not protect the RTCP packet.', 0, $e);
        }
    }

    /** @throws SrtpException If authentication fails or the packet is malformed/replayed. */
    public function unprotectRtcp(string $packet): string
    {
        $this->assertReady();
        try {
            $minimum = 8 + 4 + $this->rtcpTagLength;
            if (\strlen($packet) < $minimum) {
                throw new SrtpException('SRTCP packet is too short!');
            }
            $plainLength = \strlen($packet) - 4 - $this->rtcpTagLength;
            self::validateRtcpEnvelope($packet, $plainLength);
            $header = substr($packet, 0, 8);
            $ssrc = self::rtcpSsrc($packet);
            $this->assertSsrcAllowed($ssrc);

            if ($this->aead) {
                $indexWord = substr($packet, -4);
                $tag = substr($packet, -(4 + $this->rtcpTagLength), $this->rtcpTagLength);
                $body = substr($packet, 8, -(4 + $this->rtcpTagLength));
            } else {
                $tag = substr($packet, -$this->rtcpTagLength);
                $authenticated = substr($packet, 0, -$this->rtcpTagLength);
                $expected = substr(
                    self::hmacSha1($authenticated, $this->rtcpAuthKey),
                    0,
                    $this->rtcpTagLength
                );
                if (!hash_equals($expected, $tag)) {
                    throw new SrtpException('SRTCP authentication failed!');
                }
                $indexWord = substr($authenticated, -4);
                $body = substr($authenticated, 8, -4);
            }

            $unpacked = unpack('Nindex', $indexWord);
            if ($unpacked === false) {
                throw new SrtpException('Could not parse the SRTCP index!');
            }
            $rawIndex = (int) $unpacked['index'];
            $encrypted = ($rawIndex & 0x80000000) !== 0;
            $index = $rawIndex & self::MAX_SRTCP_INDEX;

            if (!$this->aead) {
                $this->checkReplay($this->rtcpReceiveState[$ssrc] ?? null, $index, 'SRTCP');
                $payload = !$encrypted || $body === ''
                    ? $body
                    : $body ^ self::keystream(
                        $this->rtcpKey,
                        self::iv($this->rtcpSalt, $ssrc, $index),
                        \strlen($body)
                    );
            } elseif ($encrypted) {
                $payload = $this->decryptGcm(
                    $this->rtcpKey,
                    self::aeadNonce($this->rtcpSalt, $ssrc, $index),
                    $header.$indexWord,
                    $body,
                    $tag,
                    'SRTCP'
                );
                // RFC 7714 requires AEAD validation before any replay-state action.
                $this->checkReplay($this->rtcpReceiveState[$ssrc] ?? null, $index, 'SRTCP');
            } else {
                // With E=0 the RTCP packet and ESRTCP word are AAD; the cipher is only a tag.
                $empty = $this->decryptGcm(
                    $this->rtcpKey,
                    self::aeadNonce($this->rtcpSalt, $ssrc, $index),
                    $header.$body.$indexWord,
                    '',
                    $tag,
                    'SRTCP'
                );
                if ($empty !== '') {
                    throw new SrtpException('Invalid authentication-only SRTCP ciphertext!');
                }
                $this->checkReplay($this->rtcpReceiveState[$ssrc] ?? null, $index, 'SRTCP');
                $payload = $body;
            }

            $plain = $header.$payload;
            self::validateRtcpPacket($plain);
            $this->acceptReplay($this->rtcpReceiveState, $ssrc, $index);
            return $plain;
        } catch (SrtpException $e) {
            throw $e;
        } catch (Throwable $e) {
            throw new SrtpException('Could not unprotect the SRTCP packet.', 0, $e);
        }
    }

    /** @return array{seq: int, ssrc: int} */
    private static function rtpFields(string $packet): array
    {
        $fields = unpack('nseq/Ntimestamp/Nssrc', substr($packet, 2, 10));
        if ($fields === false) {
            throw new SrtpException('Could not parse the RTP header!');
        }
        return ['seq' => (int) $fields['seq'], 'ssrc' => (int) $fields['ssrc']];
    }

    private static function rtcpSsrc(string $packet): int
    {
        $field = unpack('Nssrc', substr($packet, 4, 4));
        if ($field === false) {
            throw new SrtpException('Could not parse the RTCP SSRC!');
        }
        return (int) $field['ssrc'];
    }

    /**
     * Estimate an index relative to the greatest accepted index, following RFC 3711 Appendix A
     * with the initial-ROC guard used by interoperable implementations.
     *
     * @return array{roc: int, index: int, difference: int}
     */
    private static function estimateIndex(int $highestIndex, int $seq): array
    {
        $localRoc = intdiv($highestIndex, self::SEQ_MODULO);
        $localSeq = $highestIndex & 0xFFFF;
        $roc = $localRoc;
        $difference = $seq - $localSeq;

        if ($highestIndex > self::SEQ_MEDIAN) {
            if ($localSeq < self::SEQ_MEDIAN && $seq - $localSeq > self::SEQ_MEDIAN) {
                $roc = $localRoc - 1;
                $difference -= self::SEQ_MODULO;
            } elseif ($localSeq >= self::SEQ_MEDIAN && $localSeq - self::SEQ_MEDIAN > $seq) {
                if ($localRoc === self::MAX_ROC) {
                    throw new SrtpException('The SRTP packet limit for this key has been reached; re-keying is required.');
                }
                $roc = $localRoc + 1;
                $difference += self::SEQ_MODULO;
            }
        }

        return ['roc' => $roc, 'index' => $highestIndex + $difference, 'difference' => $difference];
    }

    /** @return array{int, int, ?string} ROC, packet index, and a cached retransmission. */
    private function reserveOutgoingRtp(int $ssrc, int $seq, string $packet): array
    {
        if ($this->rtpKeyInvocations >= self::MAX_SRTP_INVOCATIONS) {
            throw new SrtpException('The SRTP packet limit for this key has been reached; re-keying is required.');
        }
        $this->rtpKeyInvocations++;
        if (!isset($this->rtpSendState[$ssrc])) {
            $index = $seq;
            $this->rtpSendState[$ssrc] = ['highestIndex' => $index, 'sent' => []];
            $estimate = ['roc' => 0, 'index' => $index, 'difference' => 0];
        } else {
            $estimate = self::estimateIndex($this->rtpSendState[$ssrc]['highestIndex'], $seq);
        }

        /** @psalm-suppress UnsupportedPropertyReferenceUsage Psalm cannot model a reference into an array property; the alias is local and correct. */
        $state = &$this->rtpSendState[$ssrc];
        $index = $estimate['index'];
        if (isset($state['sent'][$index])) {
            $previous = $state['sent'][$index];
            if (
                $this->allowRepeatTx
                && $previous['generation'] === $this->keyGeneration
                && $previous['packet'] === $packet
                && $previous['protected'] !== null
            ) {
                return [$estimate['roc'], $index, $previous['protected']];
            }
            throw new SrtpException('Refusing to reuse an SRTP packet index!');
        }
        if ($state['highestIndex'] - $index >= $this->windowSize) {
            throw new SrtpException('Outgoing SRTP packet index is too old to use safely!');
        }

        if ($estimate['difference'] > 0) {
            $state['highestIndex'] = $index;
        }
        // Reserve before invoking a primitive. A failed invocation may not safely be retried.
        $state['sent'][$index] = [
            'packet' => $packet,
            'protected' => null,
            'generation' => $this->keyGeneration,
        ];
        $this->pruneWindow($state['sent'], $state['highestIndex']);
        return [$estimate['roc'], $index, null];
    }

    private function commitOutgoingRtp(int $ssrc, int $index, string $protected): void
    {
        if (!isset($this->rtpSendState[$ssrc]['sent'][$index])) {
            throw new SrtpException('SRTP send state was lost before protection completed!');
        }
        $this->rtpSendState[$ssrc]['sent'][$index]['protected'] = $protected;
    }

    /** @return array{int, int} ROC and packet index. */
    private function estimateIncomingRtp(int $ssrc, int $seq): array
    {
        if (!isset($this->rtpReceiveState[$ssrc])) {
            return [0, $seq];
        }
        $estimate = self::estimateIndex($this->rtpReceiveState[$ssrc]['highestIndex'], $seq);
        return [$estimate['roc'], $estimate['index']];
    }

    /** @param array{highestIndex: int, received: array<int, true>}|null $state */
    private function checkReplay(?array $state, int $index, string $protocol): void
    {
        if ($state === null) {
            return;
        }
        if ($state['highestIndex'] - $index >= $this->windowSize) {
            throw new SrtpException("$protocol packet is too old!");
        }
        if (isset($state['received'][$index])) {
            throw new SrtpException("Replayed $protocol packet!");
        }
    }

    /** @param array<int, array{highestIndex: int, received: array<int, true>}> $states */
    private function acceptReplay(array &$states, int $ssrc, int $index): void
    {
        if (!isset($states[$ssrc])) {
            $states[$ssrc] = ['highestIndex' => $index, 'received' => [$index => true]];
            return;
        }
        $state = &$states[$ssrc];
        if ($index > $state['highestIndex']) {
            $state['highestIndex'] = $index;
        }
        $state['received'][$index] = true;
        $this->pruneWindow($state['received'], $state['highestIndex']);
    }

    /** @param array<int, mixed> $entries */
    private function pruneWindow(array &$entries, int $highestIndex): void
    {
        $oldest = $highestIndex - $this->windowSize + 1;
        foreach ($entries as $index => $_) {
            if ($index < $oldest) {
                unset($entries[$index]);
            }
        }
    }

    private function decryptGcm(
        string $key,
        string $nonce,
        string $aad,
        string $ciphertext,
        string $tag,
        string $protocol
    ): string {
        if (\strlen($ciphertext) > self::MAX_GCM_PLAINTEXT_BYTES) {
            throw new SrtpException("$protocol ciphertext exceeds the AES-GCM per-invocation limit!");
        }
        if (\strlen($tag) !== 16) {
            throw new SrtpException("$protocol authentication tag has an invalid length!");
        }
        try {
            // GCM with a 96-bit nonce encrypts from inc32(J0) = nonce || 2. Derive a candidate
            // plaintext without releasing it, then run the authenticated encryption direction
            // and compare its complete result in constant time. This avoids phpseclib's portable
            // GCM decrypt path, whose tag comparison is not constant-time.
            $ctr = new AES('ctr');
            $ctr->setKey($key);
            $ctr->setIV($nonce.pack('N', 2));
            $ctr->disablePadding();
            $plain = $ctr->decrypt($ciphertext);
            $verified = $this->encryptGcm($key, $nonce, $aad, $plain, $protocol);
            $expectedCiphertext = substr($verified, 0, -16);
            $expectedTag = substr($verified, -16);
        } catch (Throwable $e) {
            if ($e instanceof SrtpException) {
                throw $e;
            }
            throw new SrtpException("$protocol authentication failed!", 0, $e);
        }
        $ciphertextValid = hash_equals($expectedCiphertext, $ciphertext);
        $tagValid = hash_equals($expectedTag, $tag);
        if (!$ciphertextValid || !$tagValid) {
            throw new SrtpException("$protocol authentication failed!");
        }
        return $plain;
    }

    /** Return ciphertext followed by its full RFC 7714 authentication tag. */
    private function encryptGcm(
        string $key,
        string $nonce,
        string $aad,
        string $plaintext,
        string $protocol
    ): string {
        if (\strlen($plaintext) > self::MAX_GCM_PLAINTEXT_BYTES) {
            throw new SrtpException("$protocol plaintext exceeds the AES-GCM per-invocation limit!");
        }
        try {
            $aes = new AES('gcm');
            $aes->setKey($key);
            $aes->setNonce($nonce);
            $aes->setAAD($aad);
            $ciphertext = $aes->encrypt($plaintext);
            $tag = $aes->getTag();
        } catch (Throwable $e) {
            throw new SrtpException("$protocol encryption failed!", 0, $e);
        }
        if (\strlen($tag) !== 16) {
            throw new SrtpException("$protocol encryption returned an invalid result!");
        }
        return $ciphertext.$tag;
    }

    /** Return a full binary HMAC-SHA1 result or fail closed. */
    private static function hmacSha1(string $message, string $key): string
    {
        $result = hash_hmac('sha1', $message, $key, true);
        if (\strlen($result) !== self::AUTH_KEY_LENGTH) {
            throw new SrtpException('HMAC-SHA1 returned an invalid result!');
        }
        return $result;
    }

    /** @throws SrtpException If a specific-SSRC policy does not match the packet. */
    private function assertSsrcAllowed(int $ssrc): void
    {
        if (isset($this->retiredSsrc[$ssrc])) {
            throw new SrtpException('The packet SSRC was removed and cannot be reused with the same key!');
        }
        if ($this->ssrcType === SsrcType::SPECIFIC && $ssrc !== $this->ssrcValue) {
            throw new SrtpException('The packet SSRC does not match the installed SRTP policy!');
        }
    }

    /** @throws SrtpValidateException If the SSRC is not an unsigned decimal 32-bit value. */
    private static function normalizeSsrc(int|string $ssrc): int
    {
        if (\is_int($ssrc)) {
            if ($ssrc < 0 || $ssrc > 0xFFFFFFFF) {
                throw new SrtpValidateException('The SSRC must be an unsigned 32-bit integer.');
            }
            return $ssrc;
        }
        if (!preg_match('/^(?:0|[1-9][0-9]*)$/D', $ssrc)) {
            throw new SrtpValidateException('The SSRC must be an unsigned decimal 32-bit integer.');
        }
        $normalized = ltrim($ssrc, '0');
        $normalized = $normalized === '' ? '0' : $normalized;
        if (\strlen($normalized) > 10 || (\strlen($normalized) === 10 && $normalized > '4294967295')) {
            throw new SrtpValidateException('The SSRC must be an unsigned 32-bit integer.');
        }
        return (int) $normalized;
    }

    /** @throws SrtpException If no key was installed. */
    private function assertReady(): void
    {
        if (!$this->ready) {
            throw new SrtpException('The SRTP session has no key!');
        }
    }
}
