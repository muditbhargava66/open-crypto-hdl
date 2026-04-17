# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-04-17

### Added
- Integrated **AES-256-GCM** AEAD logic wrapper (NIST SP 800-38D).
- Integrated **ChaCha20-Poly1305** AEAD logic wrapper (RFC 8439).
- Unified top-level FSM supporting both raw block modes and AEAD streaming modes.
- Core sharing architecture: shared single instances of AES, ChaCha20, and Poly1305 across all modes to optimize area.
- 2-stage CDC synchronizers for SPI clock (`SCK`), data (`MOSI`), and chip-select (`CS_N`).
- Encryption/Decryption direction control for DES via `CIPHER_SEL` register.
- AEAD streaming support in `spi_driver.py`.

### Changed
- **Major**: Consolidated all nested `rtl/` subdirectories into a flat `src/` directory.
- Updated `open_crypto_hdl.core` and `Makefile` to reflect source flattening.
- Increased total cell count to **37,285** to accommodate AEAD protocol state machines.
- Timing sign-off updated to **20 MHz** for multi-corner PVT safety.

### Fixed
- Poly1305 width mismatches and modular reduction logic.
- DES expected KAT vector for PT=0x1 in cocotb.
- Duplicate `tt-klayout` recipe warnings in `Makefile`.

## [1.0.0] - 2026-04-17

### Added
- Area-optimized iterative architectures for **AES-256**, **ChaCha20**, and **DES**.
- Bit-serial shift-add multiplier for **Poly1305**.
- SPI register-file interface for cipher control.
- Formal verification suites for AES and ChaCha20 safety properties.
- Support for TinyTapeout (sky130A) 2x2 tile implementation.
- Detailed architecture and pinout documentation.

[1.1.0]: https://github.com/muditbhargava66/open-crypto-hdl/releases/tag/v1.1.0
[1.0.0]: https://github.com/muditbhargava66/open-crypto-hdl/releases/tag/v1.0.0
