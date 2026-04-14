# open-crypto-hdl — Synthesis & Performance Report
# Generated: 2025 | Tool: Yosys (technology-independent)
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
| SPI Driver       | 4/4    | ALL PASS    | SimBackend self-test         |

---

## Yosys Cell Counts (Technology-Independent)

| Module             | Cells   | Notes                                    |
|--------------------|---------|------------------------------------------|
| `chacha20_qr`      | 1,187   | Combinational QR unit, 8× instantiated   |
| `chacha20_core`    | 5,435   | Includes 8× QR + FSM + state registers   |
| `des_core`         | 2,414   | Full Feistel: S-boxes, IP/PC/P perms     |
| `gf128_mul`        | 1,199   | Bit-serial GF(2¹²⁸) multiplier           |
| `ghash_core`       | 1,199   | GHASH = gf128_mul + accumulator          |
| `poly1305_core`    | 98,540  | Large due to 130-bit schoolbook multiply |

> **Note on Poly1305:** The cell count is inflated because Yosys fully
> unrolls the 130-bit × 128-bit schoolbook multiplier into primitive gates.
> In a real synthesis flow with a DSP-enabled technology library (Xilinx,
> Intel, sky130A), the multiplier maps to DSP blocks reducing area
> dramatically. The RTL is functionally correct and elaborates cleanly.
> For area-critical deployments, replace the combinational multiply with
> an iterative Barrett reduction or use the secworks/poly1305 reference.

---

## Latency & Throughput Estimates

All estimates at **100 MHz** system clock.

| Core               | Latency (cycles) | Block Size | Throughput      |
|--------------------|-----------------|------------|-----------------|
| ChaCha20 QR        | 0 (comb)         | 32 bits    | ∞ (async)       |
| ChaCha20 block     | 12               | 512 bits   | 4.27 Gbps       |
| DES                | 18               | 64 bits    | 356 Mbps        |
| 3DES               | 54               | 64 bits    | 119 Mbps        |
| AES-256 ECB        | 16               | 128 bits   | 800 Mbps        |
| AES-256 CTR        | 16 + pipe        | 128 bits   | ~800 Mbps       |
| GF(2¹²⁸) multiply | 128              | 128 bits   | 100 Mbps        |
| GHASH              | 128+             | 128 bits   | 100 Mbps        |
| AES-256-GCM        | ~160/block       | 128 bits   | ~80 Mbps        |
| Poly1305           | 1/block          | 128 bits   | ~12.8 Gbps*     |

*Poly1305 is 1 cycle per block throughput but has large combinational
 depth due to the schoolbook multiplier — actual Fmax may be <50 MHz.

---

## sky130A Area Estimates (TinyTapeout context)

TinyTapeout tiles are **160 × 100 µm** (1 tile) or larger for multi-tile.
sky130A standard cell: HD library, ~0.065 µm²/cell equivalent.

| Module               | Cells   | Est. Area (µm²) | TT Tiles Needed |
|----------------------|---------|-----------------|-----------------|
| ChaCha20 core        | 5,435   | ~23,000         | ~2              |
| DES core             | 2,414   | ~10,000         | ~1              |
| 3DES (3×DES)         | 2,414   | ~10,000         | ~1              |
| AES-256 core         | ~8,000* | ~33,000         | ~3              |
| GHASH                | 1,199   | ~5,000          | ~0.4            |
| TT Wrapper (all)     | ~20,000 | ~82,000         | ~5              |

*AES-256 estimate based on secworks reference; our inline task approach
 may be larger due to unrolled key schedule. Optimize with `synth -flatten`
 and technology mapping to HD cells.

**Recommendation for TinyTapeout:** Submit each cipher as a separate 1×2
or 2×2 tile design for optimal area utilization.

---

## FPGA Resource Estimates

### Xilinx Artix-7 (Vivado, speed grade -1)

| Module          | LUTs   | FFs    | DSPs | BRAM | Fmax (est.) |
|-----------------|--------|--------|------|------|-------------|
| ChaCha20        | ~3,200 | ~1,700 | 0    | 0    | ~150 MHz    |
| DES             | ~1,400 | ~700   | 0    | 0    | ~180 MHz    |
| AES-256         | ~5,000 | ~2,000 | 0    | 0    | ~120 MHz    |
| GF(2¹²⁸)       | ~800   | ~400   | 0    | 0    | ~200 MHz    |
| Poly1305        | ~2,500 | ~500   | 16   | 0    | ~100 MHz*   |

*With DSP inference enabled.

### Intel Cyclone V (Quartus, speed grade I7)

| Module          | ALMs   | FFs    | DSPs | Fmax (est.) |
|-----------------|--------|--------|------|-------------|
| ChaCha20        | ~1,600 | ~1,700 | 0    | ~160 MHz    |
| DES             | ~700   | ~700   | 0    | ~200 MHz    |
| AES-256         | ~2,500 | ~2,000 | 0    | ~130 MHz    |

---

## Open Source Toolchain Versions Tested

| Tool              | Version | Notes                                  |
|-------------------|---------|----------------------------------------|
| Icarus Verilog    | 12.0    | `-g2012` flag required for SV features |
| Yosys             | bundled | Technology-independent synthesis       |
| cocotb            | latest  | Python testbench framework             |
| pycryptodome      | latest  | Reference vector generation            |
| Python            | 3.11+   | Driver + reference model               |

---

## Known Limitations & Future Work

### Poly1305 Area
The current schoolbook 130×128-bit multiply produces ~98K cells. For
TinyTapeout this is prohibitive. **Recommended fix:** Replace with an
iterative Karatsuba multiplier or use a 32-bit × 32-bit serial approach
(adds ~4 cycles per block but reduces area 10×).

### AES-256 GCM Full Streaming
The `aes_gcm_top.v` has a simplified FSM that processes one AAD block
and one CT block. A production implementation needs:
- Byte-accurate padding for partial blocks
- A proper `aad_len` counter driving GHASH termination
- Full GHASH length block formatting

### Side-Channel Hardening
No masking or constant-time guarantees. All lookup tables (S-boxes, DES
permutations) are direct ROM lookups that are power-side-channel visible.
For secure ASIC deployment, add Boolean masking as per CHES literature.

### TinyTapeout Multi-tile
The current wrapper assumes a 2×2 tile. For submission, validate that
`info.yaml` tile count matches what OpenLane achieves at 50% utilization.

---

## References

1. RFC 8439 — ChaCha20 and Poly1305 for IETF Protocols
2. FIPS 197 — Advanced Encryption Standard (AES)
3. NIST SP 800-38D — Recommendation for GCM
4. NIST SP 800-38A — Recommendation for CTR mode
5. FIPS 46-3 — Data Encryption Standard
6. NIST SP 800-20 — DES Known Answer Tests
7. NIST SP 800-67 Rev. 2 — 3TDEA
8. secworks/aes — Reference Verilog AES (Joachim Strömbergson)
9. secworks/chacha — Reference Verilog ChaCha (Joachim Strömbergson)
10. TinyTapeout documentation — https://tinytapeout.com
