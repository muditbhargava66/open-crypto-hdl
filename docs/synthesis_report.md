# open-crypto-hdl — Synthesis & Performance Report
# Generated: 2026 | Tool: Yosys (technology-independent)
# ============================================================

## Simulation Verification Summary

| Core             | Tests  | Status      | Standard Reference           |
|------------------|--------|-------------|------------------------------|
| ChaCha20         | 31/31  | ALL PASS    | RFC 8439 Appendix A          |
| DES              | 19/19  | ALL PASS    | NIST SP 800-20, FIPS 81      |
| 3DES (EDE)       |  2/2   | ALL PASS    | NIST SP 800-67               |
| AES-256          |  5/5   | cocotb PASS | FIPS 197 Appendix C.3        |
| GF(2^128) mul    |  4/4   | cocotb PASS | NIST SP 800-38D              |
| GHASH            |  4/4   | cocotb PASS | NIST SP 800-38D S6.4         |
| Poly1305         |  3/3   | cocotb PASS | RFC 8439 S2.5.2              |
| AES-CTR          |  3/3   | cocotb PASS | NIST SP 800-38A S6.5         |
| AES-GCM top      |  3/3   | cocotb PASS | NIST SP 800-38D              |
| ChaCha20-Poly1305|  3/3   | cocotb PASS | RFC 8439 S2.8                |
| TT Wrapper       | n/a    | Elab OK     | TinyTapeout pin spec         |

---

## Yosys Cell Counts (Area-Optimized Iterative Cores)

| Module             | Cells   | Notes                                    |
|--------------------|---------|------------------------------------------|
| `chacha20_qr`      | 8       | Single shared QR unit (4 add, 4 xor)     |
| `chacha20_core`    | 267     | Iterative: 1 QR/cycle, rotating state    |
| `des_core`         | 802     | Iterative: 1 round/cycle, precomputed keys|
| `aes_core`         | 2,823   | Iterative: 4 S-boxes shared, 4 cycles/step|
| `poly1305_core`    | 1,034   | Bit-serial multiplier modulo 2^130 - 5   |
| `tt_um_crypto_top` | 4,666   | Full wrapper including SPI and all cores |

---

## Latency & Throughput Estimates

All estimates at **100 MHz** system clock.

| Core               | Latency (cycles) | Block Size | Throughput      |
|--------------------|------------------|------------|-----------------|
| ChaCha20 block     | 82               | 512 bits   | 624 Mbps        |
| DES                | 18               | 64 bits    | 355 Mbps        |
| 3DES               | 54               | 64 bits    | 118 Mbps        |
| AES-256 ECB        | ~235             | 128 bits   | 54 Mbps         |
| Poly1305           | 132              | 128 bits   | 96 Mbps         |
| AES-256-GCM        | ~400             | 128 bits   | ~32 Mbps        |

---

## sky130A Area Estimates (TinyTapeout context)

TinyTapeout tiles are **160 × 100 µm** (1 tile).
sky130A standard cell: HD library, ~0.065 µm²/cell equivalent.

| Module               | Cells   | Est. Area (µm²) | TT Tiles Needed |
|----------------------|---------|-----------------|-----------------|
| TT Wrapper (All)     | 4,666   | ~18,000         | 1 (2x2 recom.)  |

The entire cryptographic suite (AES-256, ChaCha20, DES, Poly1305) now fits within a single 2x2 TinyTapeout tile setup with >50% routing margin.

---

## Open Source Toolchain Versions Tested

| Tool              | Version | Notes                                  |
|-------------------|---------|----------------------------------------|
| Icarus Verilog    | 11.0    | `-g2012` flag required for SV features |
| Yosys             | 0.9     | Technology-independent synthesis       |
| cocotb            | 2.0.1   | Python testbench framework             |
| Verilator         | 5.0+    | Linting and static analysis            |

---

## References

1. RFC 8439 — ChaCha20 and Poly1305 for IETF Protocols
2. FIPS 197 — Advanced Encryption Standard (AES)
3. NIST SP 800-38D — Recommendation for GCM
4. FIPS 46-3 — Data Encryption Standard
5. TinyTapeout documentation — https://tinytapeout.com
