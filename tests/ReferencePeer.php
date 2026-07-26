<?php

namespace Tests\Webrtc\Srtp;

use PHPUnit\Framework\Assert;
use RuntimeException;

/**
 * Drives the pion-backed SRTP oracle shipped in the reference/ directory.
 *
 * Checking protect()/unprotect() against each other only proves the two halves agree; it
 * says nothing about whether the bytes on the wire are the ones the rest of the world
 * expects. Every assertion that matters here therefore goes through a real, independent
 * implementation.
 *
 * The process is kept alive across a whole test class: starting Go once per vector
 * dominated the runtime of the suite.
 */
final class ReferencePeer
{
    /** @var resource|null */
    private $process = null;

    /** @var array<int, resource> */
    private array $pipes = [];

    private function __construct(private readonly string $binary)
    {
    }

    /**
     * Locate the oracle, or skip the calling test when it has not been built.
     *
     * The binary is deliberately not required: a checkout of this package on its own has no
     * Go toolchain and should still be able to run everything that does not need a peer.
     */
    public static function create(): self
    {
        $binary = getenv('PHP_RTC_REFERENCE_BIN')
            ?: __DIR__ . '/../../reference/bin/refpeer-srtp';

        if (!is_file($binary) || !is_executable($binary)) {
            Assert::markTestSkipped(
                "The SRTP reference peer is not built. Run: (cd reference && go build -o bin/refpeer-srtp ./cmd/refpeer-srtp)"
            );
        }

        return new self($binary);
    }

    /**
     * Protect an RTP packet with the reference implementation.
     */
    public function protect(string $profile, string $key, string $packet): string
    {
        return $this->call('protect', $profile, $key, $packet);
    }

    /**
     * Unprotect an SRTP packet with the reference implementation.
     */
    public function unprotect(string $profile, string $key, string $packet): string
    {
        return $this->call('unprotect', $profile, $key, $packet);
    }

    public function protectRtcp(string $profile, string $key, string $packet): string
    {
        return $this->call('protect_rtcp', $profile, $key, $packet);
    }

    public function unprotectRtcp(string $profile, string $key, string $packet): string
    {
        return $this->call('unprotect_rtcp', $profile, $key, $packet);
    }

    /**
     * @throws RuntimeException If the peer reports an error or stops responding.
     */
    private function call(string $op, string $profile, string $key, string $packet): string
    {
        $this->start();

        $request = json_encode([
            'op' => $op,
            'profile' => $profile,
            'key' => bin2hex($key),
            'packet' => bin2hex($packet),
        ], JSON_THROW_ON_ERROR);

        fwrite($this->pipes[0], $request . "\n");
        fflush($this->pipes[0]);

        $line = fgets($this->pipes[1]);
        if ($line === false) {
            throw new RuntimeException(
                'The SRTP reference peer stopped responding: ' . stream_get_contents($this->pipes[2])
            );
        }

        $response = json_decode($line, true, 512, JSON_THROW_ON_ERROR);
        if (isset($response['error'])) {
            throw new RuntimeException("The SRTP reference peer rejected $op: {$response['error']}");
        }

        return hex2bin($response['result']);
    }

    private function start(): void
    {
        if ($this->process !== null) {
            return;
        }

        $process = proc_open(
            [$this->binary],
            [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes
        );

        if (!\is_resource($process)) {
            throw new RuntimeException("Could not start the SRTP reference peer at {$this->binary}");
        }

        // Errors are read only after a failure, so this must not block the exchange.
        stream_set_blocking($pipes[2], false);

        $this->process = $process;
        $this->pipes = $pipes;
    }

    public function stop(): void
    {
        if ($this->process === null) {
            return;
        }

        foreach ($this->pipes as $pipe) {
            if (\is_resource($pipe)) {
                fclose($pipe);
            }
        }
        proc_close($this->process);

        $this->process = null;
        $this->pipes = [];
    }

    public function __destruct()
    {
        $this->stop();
    }
}
