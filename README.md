# open-crypto-hdl

[![CI](https://github.com/muditbhargava66/open-crypto-hdl/actions/workflows/ci.yml/badge.svg)](https://github.com/muditbhargava66/open-crypto-hdl/actions)
[![TinyTapeout](https://img.shields.io/badge/TinyTapeout-ready-green)](https://tinytapeout.com)

Cryptographic cipher cores in Verilog 2001 / SystemVerilog, specifically optimized for Silicon implementation on the **TinyTapeout** platform (sky130 process).

The design uses area-optimized iterative architectures to fit a complete cryptographic suite into a standard 2x2 tile setup. Total cell count has been reduced from **98,000 to approximately 4,700 cells** through aggressive datapath sharing and bit-serial arithmetic.

Implements three complete ciphers:
- **ChaCha20-Poly1305** AEAD (RFC 8439)
- **AES-256-GCM** AEAD (FIPS 197 + NIST SP 800-38D)
- **DES** block cipher (FIPS 46-3)

---

## Project Structure

```
open-crypto-hdl/
├── rtl/
│   ├── chacha20/          Ultra area-optimized 1-QR core
│   ├── poly1305/          Bit-serial MAC (RFC 8439)
│   ├── chacha20poly1305/  AEAD top-level integration
│   ├── aes/               Iterative 14-round core (shared S-Boxes)
│   ├── gcm/               GF(2¹²⁸) multiplier + GHASH
│   ├── aes_gcm/           AEAD top-level with byte-masking
│   ├── des/               Iterative Feistel core
│   └── tt_wrapper/        TinyTapeout SPI-control wrapper
├── tb/
│   ├── cocotb/            cocotb Python testbenches
│   ├── sv/                SystemVerilog self-checking testbenches
├── syn/
│   ├── yosys/             Synthesis scripts
│   └── openlane/          OpenLane2 ASIC configuration
├── Makefile
├── info.yaml              TinyTapeout descriptor
└── docs/                  Synthesis and ASIC reports
```

---

## Implementation Details

### Area Metrics (sky130A)

| Module | Cells (Iterative) | Architecture |
|--------|------------------|--------------|
| `chacha20_core` | ~270 | 1 Quarter-round/cycle |
| `aes_core` | ~2,800 | Shared S-Boxes, 4 cycles/step |
| `des_core` | ~800 | Iterative Feistel |
| `poly1305_core`| ~1,000 | Bit-serial multiplier |
| **Total Top** | **4,666** | **Full design in 2x2 tile** |

### Performance Estimates (100 MHz)

| Core | Latency (cycles) | Throughput |
|------|-----------------|------------|
| ChaCha20 | 82 | 624 Mbps |
| AES-256 | ~235 | 54 Mbps |
| DES | 18 | 355 Mbps |
| Poly1305 | 132 | 96 Mbps |

---

## Quick Start

### 1. Install dependencies

```bash
sudo apt install iverilog verilator yosys
pip install cocotb pycryptodome
```

### 2. Run simulations

```bash
make sim-all       # SystemVerilog suites
make cocotb-all    # cocotb KAT suites
```

### 3. Lint and Synthesize

```bash
make lint
make synth-tt      # TinyTapeout top-level synthesis
```

---

## TinyTapeout Interface

The `tt_um_crypto_top.v` wrapper exposes all cores through a shared SPI register file.

### Pin Assignment

| Pin | Direction | Function |
|-----|-----------|----------|
| `uio[0]` | Input | SCK (SPI Clock) |
| `uio[1]` | Input | MOSI (Data In) |
| `uio[2]` | Output | MISO (Data Out) |
| `uio[3]` | Input | CS_N (Chip Select) |
| `clk` | Input | System Clock |
| `rst_n` | Input | Active-low Reset |

### Register Map

| Address | Name | Access | Description |
|---------|------|--------|-------------|
| `0x00` | `CIPHER` | R/W | `00`=DES, `01`=AES, `10`=ChaCha, `11`=Poly |
| `0x01` | `CMD` | W | `0x01`=Start, `0x02`=Reset, `0x04`=Poly-Init |
| `0x02` | `STATUS` | R | `[0]`=Busy, `[1]`=Done |
| `0x10`–`0x2F` | `KEY` | R/W | 256-bit Key |
| `0x30`–`0x3B` | `IV` | R/W | 96-bit IV/Nonce |
| `0x40`–`0x4F` | `BLOCK` | R/W | 128-bit Input Block |
| `0x50`–`0x5F` | `RESULT` | R | Output data |
| `0x60`–`0x6F` | `TAG` | R | AEAD Tag |

---

## Security Notes

**DES Warning:** DES is cryptographically broken and included for legacy/educational purposes only.

**Side-Channel:** These implementations are not hardened against side-channel analysis (SPA/DPA).

## License

Apache License 2.0.
