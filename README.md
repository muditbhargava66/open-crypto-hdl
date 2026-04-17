# open-crypto-hdl

[![CI](https://github.com/muditbhargava66/open-crypto-hdl/actions/workflows/ci.yml/badge.svg)](https://github.com/muditbhargava66/open-crypto-hdl/actions)
[![TinyTapeout](https://img.shields.io/badge/TinyTapeout-ready-green)](https://tinytapeout.com)

Cryptographic cipher cores in Verilog 2001 / SystemVerilog, optimized for Silicon implementation on the **TinyTapeout** platform (sky130 process).

The design uses area-optimized iterative architectures to fit a complete cryptographic suite into a standard 2x2 tile setup. Total cell count has been reduced from **98,000 to approximately 4,700 cells** through aggressive datapath sharing and bit-serial arithmetic.

![GDS Layout](layout.png)

Implements four cryptographic engines:
- **ChaCha20** Stream Cipher (RFC 8439)
- **Poly1305** MAC (RFC 8439)
- **AES-256** Block Cipher (FIPS 197)
- **DES** Block Cipher (FIPS 46-3)

---

## Project Structure

```
open-crypto-hdl/
├── src/
│   ├── chacha20/          Iterative 1-QR core (rotating state)
│   ├── poly1305/          Bit-serial MAC (modulo 2^130 - 5)
│   ├── aes/               Iterative 14-round core (shared S-Boxes)
│   ├── des/               Iterative Feistel core
│   └── tt_wrapper/        TinyTapeout SPI-control wrapper
├── tb/
│   ├── cocotb/            cocotb Python testbenches (NIST/RFC KAT)
│   ├── sv/                SystemVerilog self-checking testbenches
│   ├── formal/            SymbiYosys verification properties
├── syn/
│   ├── yosys/             Synthesis scripts
│   └── openlane/          OpenLane2 ASIC configuration
├── docs/                  Synthesis, STA, and ASIC reports
├── layout.png             GDS layout render
└── layout.svg             GDS vector render
```

---

## Implementation Details

### Area Metrics (sky130A)

| Module          | Cells (Flattened) | Optimization Strategy                  |
|-----------------|-------------------|----------------------------------------|
| `chacha20_core` | ~2,250            | Shared QR unit, rotating 512-bit state |
| `aes_core`      | ~6,800            | Shared S-Boxes, word-based iteration   |
| `des_core`      | ~2,500            | Classic iterative Feistel              |
| `poly1305_core` | ~7,300            | Bit-serial shift-add multiplier        |
| **Total Top**   | **37,285**        | **Unified AEAD Suite**                 |

### Performance Estimates (Multi-Corner STA)

| Core          | Max Freq (TT) | Max Freq (SS) | Throughput (at 20MHz) |
|---------------|---------------|---------------|-----------------------|
| ChaCha20      | 42 MHz        | 21 MHz        | 124 Mbps              |
| AES-256       | 42 MHz        | 21 MHz        | 10 Mbps               |
| DES           | 42 MHz        | 21 MHz        | 71 Mbps               |
| Poly1305      | 42 MHz        | 21 MHz        | 15 Mbps               |


---

## Formal Verification

The design has been formally verified using **SymbiYosys (sby)** to ensure functional correctness and safety invariants:
- **ChaCha20**: Proven progress and output gating (Depth 100).
- **AES-256**: Proven round-trip FSM transitions (Depth 300).
- **DES**: Proven Encrypt/Decrypt mathematical inverse property.

---

## Quick Start

### 1. Install dependencies

```bash
sudo apt install iverilog verilator yosys symbiyosys
pip install cocotb pycryptodome
```

### 2. Run Verification

```bash
make lint          # Static analysis
make sim-all       # SystemVerilog simulation
make cocotb-all    # cocotb functional verification
make formal-chacha # Formal property check
```

---

## TinyTapeout Interface

The `tt_um_crypto_top.v` wrapper exposes all cores through a shared SPI register file.

### SPI Register Map

| Address       | Name       | Access | Description                                                                 |
|---------------|------------|--------|-----------------------------------------------------------------------------|
| `0x00`        | `CIPHER`   | R/W    | `[2:0]`: DES(0), AES(1), ChaCha(2), Poly(3), GCM(4), C20P(5). `[3]`: 1=Enc, 0=Dec. |
| `0x01`        | `CMD`      | W      | `0x01`=Start, `0x02`=Reset, `0x04`=Poly-Init, `0x08`=AEAD-Next              |
| `0x02`        | `STATUS`   | R      | `bit 0`=Busy, `bit 1`=Done                                                  |
| `0x04`–`0x07` | `AAD_LEN`  | R/W    | 32-bit AAD Length (Big-Endian)                                              |
| `0x08`–`0x0B` | `PT_LEN`   | R/W    | 32-bit PT/CT Length (Big-Endian)                                            |
| `0x10`–`0x2F` | `KEY`      | R/W    | 256-bit Key Storage                                                         |
| `0x30`–`0x3B` | `IV`       | R/W    | 96-bit IV/Nonce                                                             |
| `0x40`–`0x4F` | `BLOCK`    | R/W    | 128-bit Input Block                                                         |
| `0x50`–`0x5F` | `RESULT`   | R      | 128-bit Output Buffer                                                       |
| `0x60`–`0x6F` | `TAG`      | R      | 128-bit Authentication Tag                                                  |

---

## License

Apache License 2.0.
