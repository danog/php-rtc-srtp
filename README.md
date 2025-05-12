# SRTP Adapter for PHP

[![PHP Version](https://img.shields.io/badge/php-%3E%3D8.4-blue.svg)](https://php.net/)
[![License](https://img.shields.io/badge/license-BSD-blue.svg)](LICENSE)

A PHP library for Secure RTP (SRTP) packet encryption and decryption using OpenSSL FFI. It enables secure media transport for WebRTC applications with support for AES encryption and HMAC authentication.

## Features

- AES-GCM and AES-CM encryption for RTP/RTCP packets
- HMAC-SHA1 authentication
- Replay protection
- Interoperable with standard WebRTC implementations
- 
## Requirements

- PHP ≥ 8.4 with FFI extension enabled
- Srtp development libraries
- Linux environment (Windows/macOS support planned)

## Documentation

This package is part of the PHP WebRTC library. For complete documentation, examples, and API reference, visit:

[PHP WebRTC Documentation](https://www.quasarstream.com/php-webrtc)

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
