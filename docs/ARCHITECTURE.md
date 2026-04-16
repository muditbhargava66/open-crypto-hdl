# open-crypto-hdl Architecture

## Design Strategy
The primary constraint for this project is the limited silicon area available in a TinyTapeout tile. To implement multiple complex cryptographic algorithms (AES-256, ChaCha20, Poly1305), we utilized iterative architectures that prioritize datapath sharing and low cell counts over raw throughput.

## Core Implementations

### AES-256 (Iterative)
The AES core processes 4 bytes (one word) per clock cycle during the SubBytes, ShiftRows, and MixColumns phases. This reduces the number of S-Boxes required from 16 to 4, which are further shared with the key expansion logic. The key schedule is generated on-the-fly to eliminate the need for a large key memory.

### ChaCha20 (Rotating State)
ChaCha20 typically requires 8 Quarter-Round (QR) units running in parallel. In this implementation, we use a single QR unit and rotate the 512-bit state registers to process the algorithm iteratively. This reduces the logic area by approximately 80% while maintaining the standard RFC 8439 behavior.

### Poly1305 (Bit-Serial Multiplier)
The bottleneck in Poly1305 is the 130-bit multiplication. Instead of a massive combinational multiplier, we implement a bit-serial shift-add multiplier with integrated modular reduction (modulo 2^130 - 5). Each 16-byte block takes ~132 cycles to process, fitting comfortably within a tiny fraction of a tile.

### DES (Standard Iterative)
The DES core uses a classic 16-round Feistel architecture. Since DES is already quite small, a single-round-per-cycle iterative approach was sufficient to meet area targets without further bit-level serialization.

## Interface and Control
A central register file managed by a SPI slave interface handles all configuration and data transport. This decoupling allows the cryptographic cores to run at the system clock speed while being driven by a slower external controller (e.g., an MCU).
