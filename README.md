# SRTP Adapter for PHP

[![PHP Version](https://img.shields.io/badge/php-%3E%3D8.2-blue.svg)](https://php.net/)
[![License](https://img.shields.io/badge/license-BSD-blue.svg)](LICENSE)

A pure-PHP library for Secure RTP (SRTP) and SRTCP packet encryption and decryption. It supports the AES-CM and AES-GCM protection profiles used by WebRTC without requiring OpenSSL or libsrtp FFI bindings.

## About this fork

This is the `danog/php-rtc-srtp` fork used by MadelineProto. It targets PHP 8.2+, replaces the upstream libsrtp binding with an RFC 3711/RFC 7714 implementation backed by phpseclib, and includes interoperability fixes verified against pion/srtp.

All internal Composer dependencies use their `danog/php-rtc-*` package names directly, so installing a component selects the maintained danog packages throughout the dependency graph.

## Features

- AES-GCM and AES-CM encryption for RTP/RTCP packets
- HMAC-SHA1 authentication
- Replay protection
- Interoperable with standard WebRTC implementations
- 
## Requirements

- PHP ≥ 8.2
- phpseclib 3 (installed through Composer)
- Linux environment (Windows/macOS support planned)

## Documentation

This package is part of the PHP WebRTC library. For complete documentation, examples, and API reference, visit:

[PHP WebRTC Documentation](https://github.com/danog/php-rtc-srtp)

## Credits

### Authors

- **Amin Yazdanpanah**  
  [aminyazdanpanah.com](https://www.aminyazdanpanah.com)
  [github@aminyazdanpanah.com](mailto:github@aminyazdanpanah.com)

- **Sana Moniri**  
  [GitHub](https://github.com/sanamoniri)

## Reporting Issues

Found a bug? Please report it on our [issues](https://github.com/php-webrtc/srtp/issues).

## License

BSD 3-Clause License. See [LICENSE](LICENSE) for details.

## References

- [RFC 3711 – The Secure Real-time Transport Protocol (SRTP)](https://datatracker.ietf.org/doc/html/rfc3711)
