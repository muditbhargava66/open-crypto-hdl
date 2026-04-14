# open-crypto-hdl

[![CI](https://github.com/muditbhargava66/open-crypto-hdl/actions/workflows/ci.yml/badge.svg)](https://github.com/muditbhargava66/open-crypto-hdl/actions)
[![TinyTapeout](https://img.shields.io/badge/TinyTapeout-ready-green)](https://tinytapeout.com)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue)](LICENSE)

Cryptographic cipher cores in Verilog 2001 / SystemVerilog,
targeting **TinyTapeout** (sky130 ASIC) and FPGA implementation.

Implements three complete ciphers:
- **ChaCha20-Poly1305** AEAD (RFC 8439)
- **AES-256-GCM** AEAD (FIPS 197 + NIST SP 800-38D)
- **DES** block cipher (FIPS 46-3)

---

## Project Structure

```
open-crypto-hdl/
├── rtl/
│   ├── chacha20/          ChaCha20 quarter-round + 20-round core
│   ├── poly1305/          Poly1305 MAC (RFC 8439)
│   ├── chacha20poly1305/  ChaCha20-Poly1305 AEAD top-level
│   ├── aes/               AES-256 S-Box + iterative 14-round core
│   ├── gcm/               GF(2¹²⁸) multiplier + GHASH
│   ├── aes_gcm/           AES-256-GCM AEAD top-level
│   ├── des/               DES 16-round Feistel core
│   └── tt_wrapper/        TinyTapeout SPI-control wrapper
├── tb/
│   ├── cocotb/            cocotb Python testbenches
│   ├── sv/                SystemVerilog self-checking testbenches
│   ├── formal/            SymbiYosys formal verification configs
│   └── reference_model.py Software reference implementation
├── syn/
│   ├── yosys/             Yosys synthesis scripts + area estimates
│   └── openlane/          OpenLane2 ASIC configuration
├── constraints/           FPGA constraint files (Arty A7 XDC)
├── .github/workflows/     GitHub Actions CI
├── Makefile
├── info.yaml              TinyTapeout descriptor
└── open_crypto_hdl.core   FuseSoC package descriptor
```

---

## Open Source Toolchain

| Stage | Tool | Description |
|-------|------|-------------|
| Simulation | [Icarus Verilog](https://github.com/steveicarus/iverilog) | Cycle-accurate RTL simulation |
| Simulation | [cocotb](https://github.com/cocotb/cocotb) | Python-based testbench framework |
| Lint | [Verilator](https://github.com/verilator/verilator) | Static lint checking |
| Synthesis | [Yosys](https://github.com/YosysHQ/yosys) | Logic synthesis + area estimation |
| Formal | [SymbiYosys](https://github.com/YosysHQ/sby) | Formal property verification |
| ASIC | [OpenLane 2](https://github.com/efabless/openlane2) | RTL-to-GDS ASIC flow |
| PDK | [sky130A](https://github.com/google/skywater-pdk) | SkyWater 130nm open PDK |
| P&R | [OpenROAD](https://github.com/The-OpenROAD-Project/OpenROAD) | Place & route |
| Package | [FuseSoC](https://github.com/olofk/fusesoc) | IP package manager |
| Format | [sv2v](https://github.com/zachjs/sv2v) | SV → Verilog conversion |

---

## Quick Start

### 1. Install dependencies

```bash
# Simulation
sudo apt install iverilog verilator
pip install cocotb pycryptodome

# Synthesis
sudo apt install yosys

# Optional: formal verification (oss-cad-suite includes sby + solvers)
# See https://github.com/YosysHQ/oss-cad-suite-build
sudo apt install yices2
```

### 2. Run simulations

```bash
# SystemVerilog testbenches (Icarus Verilog)
make sim-all              # ChaCha20, DES, 3DES

# cocotb testbenches (Python, requires cocotb + iverilog)
make cocotb-all           # All cocotb tests
make cocotb-chacha20      # RFC 8439 test vectors
make cocotb-des           # NIST KAT vectors
make cocotb-aes           # FIPS 197 Appendix C.3
make cocotb-gf128         # GF(2^128) multiplier
make cocotb-ghash         # GHASH streaming
make cocotb-poly1305      # RFC 8439 Poly1305
make cocotb-aes-ctr       # NIST SP 800-38A CTR mode
make cocotb-aes-gcm       # AES-256-GCM AEAD
make cocotb-chacha20poly1305  # ChaCha20-Poly1305 AEAD
```

### 3. Lint

```bash
make lint
```

### 4. Synthesize and get area estimates

```bash
make synth-all

# Detailed area estimate across all cores
make area-estimate
```

### 5. Generate software reference vectors

```bash
python3 tb/reference_model.py          # human-readable
python3 tb/reference_model.py --json   # JSON
python3 tb/reference_model.py --sv     # SystemVerilog localparams
```

### 6. Run formal verification

```bash
make formal-chacha
```

---

## Core Details

### ChaCha20 (`rtl/chacha20/`)

| Parameter | Value |
|-----------|-------|
| Standard | RFC 8439 |
| Key | 256-bit |
| Nonce | 96-bit |
| Counter | 32-bit |
| Output | 512-bit keystream block |
| Architecture | Iterative, 10 double-rounds |
| Latency | 12 cycles |
| Throughput | 512 bits / 12 cycles @ 100 MHz = 4.27 Gbps |

**Files:**
- `chacha20_qr.v` — combinational quarter-round unit (instantiated 8×)
- `chacha20_core.v` — 10-cycle iterative 20-round core

### Poly1305 (`rtl/poly1305/`)

| Parameter | Value |
|-----------|-------|
| Standard | RFC 8439 §2.5 |
| Key | 256-bit (r||s) |
| Block | 128-bit input |
| Tag | 128-bit MAC |
| Architecture | Iterative GF(2¹³⁰-5) multiply-accumulate |
| Latency | 1 cycle per 16-byte block |

### AES-256 (`rtl/aes/`)

| Parameter | Value |
|-----------|-------|
| Standard | FIPS 197 |
| Key | 256-bit |
| Block | 128-bit |
| Rounds | 14 |
| Architecture | Iterative, 1 round/cycle |
| Latency | 16 cycles |

**Key expansion** is performed inline on each `load` pulse using a pipelined
key schedule task, avoiding a separate pre-expansion phase.

### GF(2¹²⁸) Multiplier (`rtl/gcm/gf128_mul.v`)

Implements the GCM field multiply with reduction polynomial
p(x) = x¹²⁸ + x⁷ + x² + x + 1. Bit-serial implementation:
128-cycle latency. A parallel unrolled version is straightforward
to generate with generate blocks for higher-frequency designs.

### DES (`rtl/des/`)

| Parameter | Value |
|-----------|-------|
| Standard | FIPS 46-3 |
| Key | 64-bit (56 effective) |
| Block | 64-bit |
| Rounds | 16 |
| Architecture | Iterative Feistel, 1 round/cycle |
| Latency | 18 cycles |
| Encrypt/Decrypt | Selectable via `encrypt` port |

Full implementation including IP/IP⁻¹, PC1/PC2, E-expansion,
all 8 S-boxes, and P-box permutation.

### ChaCha20-Poly1305 (`rtl/chacha20poly1305/`)

Full AEAD integration per RFC 8439 §2.8:
1. OTK generation: ChaCha20(key, nonce, ctr=0) → Poly1305 key
2. Encryption: ChaCha20(key, nonce, ctr=1,2,...) XOR plaintext
3. MAC: Poly1305(OTK, pad(AAD) || pad(CT) || len(A) || len(C))

### AES-256-GCM (`rtl/aes_gcm/`)

Full AEAD integration per NIST SP 800-38D:
1. Hash subkey: H = AES_K(0¹²⁸)
2. Counter mode: C = GCTR_K(J₀+1, P)
3. Authentication: T = GHASH_H(A || C) ⊕ AES_K(J₀)

---

## TinyTapeout Interface

The `tt_um_crypto_top.v` wrapper exposes all three ciphers through
a shared SPI register file.

### Pin Assignment

| Pin | Direction | Function |
|-----|-----------|----------|
| `ui_in[3:0]` | Input | Result byte selector (0–15) |
| `uo_out[7:0]` | Output | Result register byte output |
| `uio[0]` (SCK) | Input | SPI clock |
| `uio[1]` (MOSI) | Input | SPI data in |
| `uio[2]` (MISO) | Output | SPI data out |
| `uio[3]` (CS_N) | Input | SPI chip select (active low) |
| `ena` | Input | Design enable |
| `clk` | Input | System clock (50 MHz) |
| `rst_n` | Input | Active-low reset |

### SPI Register Map

| Address | Name | Access | Description |
|---------|------|--------|-------------|
| `0x00` | `CIPHER_SEL` | R/W | `00`=DES, `01`=AES, `10`=ChaCha20 |
| `0x01` | `CMD` | W | `0x01`=start, `0x02`=reset |
| `0x02` | `STATUS` | R | `[0]`=busy, `[1]`=done |
| `0x10`–`0x1F` | `KEY[0:15]` | R/W | Key bytes 0–15 |
| `0x20`–`0x2F` | `KEY[16:31]` | R/W | Key bytes 16–31 (AES/ChaCha) |
| `0x30`–`0x3B` | `IV[0:11]` | R/W | IV/nonce bytes |
| `0x40`–`0x4F` | `BLOCK_IN[0:15]` | R/W | Input block |
| `0x50`–`0x5F` | `RESULT[0:15]` | R | Ciphertext output |
| `0x60`–`0x6F` | `TAG[0:15]` | R | AEAD authentication tag |

---

## Test Coverage

| Core | Test Type | Tests | Vector Source |
|------|-----------|:-----:|---------------|
| ChaCha20 | cocotb + SV | 3+31 | RFC 8439 §A |
| DES | cocotb + SV | 2+19 | NIST FIPS 81, NIST SP 800-20 |
| AES-256 | cocotb | 5 | NIST FIPS 197 Appendix C.3, NIST AESAVS |
| GF(2^128) mul | cocotb | 4 | NIST SP 800-38D |
| GHASH | cocotb | 4 | NIST SP 800-38D §6.4 |
| Poly1305 | cocotb | 3 | RFC 8439 §2.5.2 |
| AES-256-CTR | cocotb | 3 | NIST SP 800-38A §F.5.5 |
| AES-256-GCM | cocotb | 3 | NIST SP 800-38D TC16 |
| ChaCha20-Poly1305 | cocotb | 3 | RFC 8439 §A.5 |
| Formal | SymbiYosys BMC | — | ChaCha20 invariants |

**Total: 30 cocotb test functions + 52 SystemVerilog assertions.**

---

## Performance Estimates (100 MHz, sky130)

| Core | Latency | Throughput |
|------|---------|------------|
| ChaCha20 | 12 cycles | ~4.2 Gbps |
| DES | 18 cycles | ~355 Mbps |
| AES-256 ECB | 16 cycles | ~800 Mbps |
| GF128 mul | 128 cycles | ~100 Mbps |
| AES-256-GCM | ~160 cycles/block | ~80 Mbps |

*Sky130 targets approximately 50–100 MHz after place-and-route.*

---

## Security Notes

> **⚠️ DES is cryptographically broken.** This implementation is for
> educational and legacy compatibility purposes only. Do not use DES
> for any security-sensitive application.

> **⚠️ Side-channel resistance:** These RTL implementations are
> **not hardened against side-channel attacks** (timing, power, EM).
> For security-critical ASIC deployment, add Boolean masking or
> threshold implementations.

---

## License

Apache License 2.0. See [LICENSE](LICENSE).

## Contributing

Pull requests welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for
test requirements and code style guidelines.

## References

- RFC 8439: ChaCha20 and Poly1305 for IETF Protocols
- FIPS 197: Advanced Encryption Standard
- NIST SP 800-38D: GCM Recommendation
- FIPS 46-3: Data Encryption Standard
- [secworks/aes](https://github.com/secworks/aes) — reference AES Verilog
- [secworks/chacha](https://github.com/secworks/chacha) — reference ChaCha Verilog
- [TinyTapeout](https://tinytapeout.com) — open ASIC shuttle
