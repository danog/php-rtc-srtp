<?php

/**
 * This file is part of the PHP WebRTC package.
 *
 * (c) Amin Yazdanpanah <https://www.aminyazdanpanah.com/#contact>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Webrtc\Srtp\Exception;

use Throwable;

class SrtpValidateException extends SrtpException
{
    /**
     * The libsrtp status codes, kept so that a numeric status can still be rendered.
     *
     * Nothing produces these any more now that SRTP is implemented in PHP rather than bound
     * to libsrtp, but fromStatus() remains for callers translating a foreign status code.
     */
    private const ERRORS = [
        "nothing to report",
        "unspecified failure",
        "unsupported parameter",
        "couldn't allocate memory",
        "couldn't deallocate properly",
        "couldn't initialize",
        "can't process as much data as requested",
        "authentication failure",
        "cipher failure",
        "replay check failed (bad index)",
        "replay check failed (index too old)",
        "algorithm failed test routine",
        "unsupported operation",
        "no appropriate context found",
        "unable to perform desired validation",
        "can't use key any more",
        "error in use of socket",
        "error in use POSIX signals",
        "nonce check failed",
        "couldn't read data",
        "couldn't write data",
        "error parsing data",
        "error encoding data",
        "error while using semaphores",
        "error while using pfkey",
        "error MKI present in packet is invalid",
        "packet index is too old to consider",
        "packet index advanced, reset needed",
    ];

    /**
     * Build a validation failure from a description of what was wrong.
     *
     * This used to take a libsrtp status code, a signature left over from the days when the
     * package bound to that library. Every caller passes a message, so each of them raised a
     * TypeError instead of the exception the API documents.
     */
    public function __construct(string $message = '', int $code = 0, ?Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }

    /**
     * Build a validation failure from a libsrtp status code.
     */
    public static function fromStatus(int $status): self
    {
        return new self(self::ERRORS[$status] ?? 'Unknown Error!', $status);
    }
}