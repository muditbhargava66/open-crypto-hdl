"""
test_aes_ctr.py — cocotb testbench for aes_ctr.v
AES-256 Counter Mode (CTR) per NIST SP 800-38A §F.5.5.

Run:
    TOPLEVEL=aes_ctr MODULE=tb.cocotb.test_aes_ctr \
    VERILOG_SOURCES="rtl/aes/aes_sbox.v rtl/aes/aes_core.v rtl/aes/aes_ctr.v" \
    SIM=icarus make -f $(cocotb-config --makefiles)/Makefile.sim
"""

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge, ClockCycles


# ── NIST SP 800-38A §F.5.5 — AES-256 CTR test vectors ───────────────────────
# Key   = 603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4
# Nonce = f0f1f2f3f4f5f6f7f8f9fafb  (first 96 bits of init counter block)
# ICtr  = fcfdfeff                   (last 32 bits)
# Full init CTR block = f0f1f2f3 f4f5f6f7 f8f9fafb fcfdfeff

NIST_KEY   = 0x603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4
NIST_NONCE = 0xf0f1f2f3f4f5f6f7f8f9fafb
NIST_ICTR  = 0xfcfdfeff

# (plaintext, expected_ciphertext) pairs — block-by-block
NIST_VECTORS = [
    (0x6bc1bee22e409f96e93d7e117393172a, 0x601ec313775789a5b7a7f504bbf3d228),
    (0xae2d8a571e03ac9c9eb76fac45af8e51, 0xf443e3ca4d62b59aca84e990cacaf5c5),
    (0x30c81c46a35ce411e5fbc1191a0a52ef, 0x2b0930daa23de94ce87017ba2d84988d),
    (0xf69f2445df4f9b17ad2b417be66c3710, 0xdfc9c58db67aada613c2dd08457941a6),
]


async def reset_dut(dut):
    """Apply reset sequence."""
    clock = Clock(dut.clk, 10, unit="ns")
    cocotb.start_soon(clock.start())
    dut.rst_n.value = 0
    dut.start.value = 0
    dut.data_valid.value = 0
    await ClockCycles(dut.clk, 4)
    dut.rst_n.value = 1
    await RisingEdge(dut.clk)


@cocotb.test()
async def test_nist_ctr_single_block(dut):
    """NIST SP 800-38A §F.5.5 — AES-256 CTR first block."""
    await reset_dut(dut)

    # Configure CTR mode
    dut.key.value = NIST_KEY
    dut.nonce.value = NIST_NONCE
    dut.initial_ctr.value = NIST_ICTR
    dut.start.value = 1
    await RisingEdge(dut.clk)
    dut.start.value = 0
    await ClockCycles(dut.clk, 2)

    # Feed first plaintext block
    pt, expected_ct = NIST_VECTORS[0]
    dut.data_in.value = pt
    dut.data_valid.value = 1
    await RisingEdge(dut.clk)
    dut.data_valid.value = 0

    # Wait for output
    for _ in range(500):
        await RisingEdge(dut.clk)
        if int(dut.data_out_valid.value) == 1:
            ct = int(dut.data_out.value)
            dut._log.info(f"CT got: 0x{ct:032x}")
            dut._log.info(f"CT exp: 0x{expected_ct:032x}")
            assert ct == expected_ct, (
                f"NIST CTR block 0 mismatch\n"
                f"  got 0x{ct:032x}\n"
                f"  exp 0x{expected_ct:032x}"
            )
            dut._log.info("✓ NIST SP 800-38A CTR block 0 PASSED")
            return

    assert False,("AES-CTR timeout")


@cocotb.test()
async def test_ctr_counter_increments(dut):
    """Verify counter auto-increments by checking ctr_out changes."""
    await reset_dut(dut)

    dut.key.value = NIST_KEY
    dut.nonce.value = NIST_NONCE
    dut.initial_ctr.value = 0
    dut.start.value = 1
    await RisingEdge(dut.clk)
    dut.start.value = 0
    await ClockCycles(dut.clk, 2)

    initial_ctr = int(dut.ctr_out.value)

    # Process one block
    dut.data_in.value = 0x00000000000000000000000000000000
    dut.data_valid.value = 1
    await RisingEdge(dut.clk)
    dut.data_valid.value = 0

    for _ in range(500):
        await RisingEdge(dut.clk)
        if int(dut.data_out_valid.value) == 1:
            new_ctr = int(dut.ctr_out.value)
            assert new_ctr == initial_ctr + 1, (
                f"Counter should increment: {initial_ctr} → {new_ctr}"
            )
            dut._log.info(f"✓ CTR auto-increment: {initial_ctr} → {new_ctr} PASSED")
            return

    assert False,("Timeout waiting for first CTR output")


@cocotb.test()
async def test_ctr_start_resets(dut):
    """Re-issuing start should reset counter and state."""
    await reset_dut(dut)

    # First start
    dut.key.value = NIST_KEY
    dut.nonce.value = NIST_NONCE
    dut.initial_ctr.value = 42
    dut.start.value = 1
    await RisingEdge(dut.clk)
    dut.start.value = 0
    await ClockCycles(dut.clk, 2)

    assert int(dut.ctr_out.value) == 42, "Counter should be 42 after start"

    # Re-start with different counter
    dut.initial_ctr.value = 100
    dut.start.value = 1
    await RisingEdge(dut.clk)
    dut.start.value = 0
    await ClockCycles(dut.clk, 2)

    assert int(dut.ctr_out.value) == 100, "Counter should be 100 after re-start"
    dut._log.info("✓ CTR start-reset PASSED")
