# Contributing to open-crypto-hdl

Thank you for considering a contribution! This project aims to be the
reference-quality open-source cryptographic RTL collection for TinyTapeout
and FPGA deployment. We hold contributions to a high bar.

---

## Coding Standards

### Verilog Style

1. **All synthesizable RTL must target Verilog 2001** (`-g2005` with Icarus).
   Testbenches may use SystemVerilog (but must be gated by a `tb/` directory).

2. **Explicit `default_nettype none`** at top and `default_nettype wire` at
   bottom of every file. This catches accidental implicit net declarations.

3. **No latches.** Every combinational assignment must be fully covered.
   Check with `verilator --lint-only -Wall`.

4. **Port naming:**
   - `clk` — single clock domain
   - `rst_n` — synchronous active-low reset
   - `*_valid` / `*_ready` — valid/ready handshake signals
   - `load` / `done` — one-cycle start/done pulses

5. **Parameters over `define`** for configurable widths.

6. **Comments:** Every module must have a header block explaining:
   - Standard reference (RFC, FIPS, NIST SP)
   - Latency in cycles
   - Interface protocol

### File Naming

```
rtl/<core_name>/<module_name>.v          Synthesizable Verilog 2001
tb/sv/<tb_name>.sv                       SystemVerilog testbench
tb/cocotb/test_<core_name>.py            cocotb testbench
tb/formal/<core_name>_formal.sby         SymbiYosys config
```

---

## New Core Checklist

Before submitting a PR for a new cipher core:

- [ ] RTL in `rtl/<core_name>/`
- [ ] Module header with standard reference and interface docs
- [ ] `default_nettype none/wire` guards
- [ ] `verilator --lint-only -Wall` passes clean
- [ ] cocotb testbench with official NIST/RFC test vectors
- [ ] SystemVerilog self-checking testbench
- [ ] Yosys synthesizes without errors (`make synth-<core>`)
- [ ] FuseSoC `.core` entry added to `open_crypto_hdl.core`
- [ ] Makefile targets added: `sim-<core>`, `synth-<core>`
- [ ] README.md updated with core specification table
- [ ] GitHub Actions CI passes

---

## Test Vector Requirements

All testbenches **must** use official test vectors:

| Cipher | Source |
|--------|--------|
| ChaCha20 | RFC 8439 Appendix A |
| Poly1305 | RFC 8439 Appendix A.3 |
| AES | NIST FIPS 197 Appendix B/C, NIST AESAVS |
| AES-GCM | NIST SP 800-38D Appendix B |
| DES | NIST SP 800-20 Appendix A, FIPS 81 |

Testbenches should also include:
- **Idempotency:** same inputs → same outputs across multiple runs
- **Counter uniqueness:** different counters → different keystreams  
- **Roundtrip:** encrypt then decrypt recovers plaintext

---

## Pull Request Process

1. Fork the repo and create a feature branch:
   ```bash
   git checkout -b feature/3des-core
   ```

2. Make your changes with atomic commits:
   ```bash
   git commit -m "rtl/des: add 3DES triple-encryption wrapper"
   ```

3. Ensure the full CI suite passes locally:
   ```bash
   make lint
   make synth-all
   make sim-chacha20 sim-des sim-aes
   ```

4. Submit PR against `main` with a description of:
   - What cipher/feature is added
   - Standard reference
   - Area estimate from Yosys (`make area-estimate`)
   - Any known limitations

---

## Areas Actively Welcoming PRs

- **Parallel GF(2^128) multiplier** (unrolled for higher throughput)
- **Iterative Poly1305 multiplier** (replacing schoolbook to reduce area)
- **Multi-block AES-GCM streaming** (extend FSM beyond single-block)
- **Formal properties** embedded in RTL for SymbiYosys
- **Intel FPGA constraint files** (.qsf for Cyclone V / MAX 10)
- **Python bindings** for the SPI protocol to the TT wrapper
- **Constant-time side-channel hardening** for AES S-Box lookup
- **3DES cocotb testbench** with NIST SP 800-67 vectors

---

## License

By contributing, you agree that your contributions will be licensed
under the Apache 2.0 License.
