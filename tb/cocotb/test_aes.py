"""
test_aes.py — cocotb testbench for aes_core.v
NIST FIPS 197 Appendix B & C test vectors (AES-256)

Run:
    make sim-aes
"""

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge, ClockCycles

# ── NIST FIPS 197 AES-256 Test Vectors ────────────────────────────────────────
# Appendix C.3 — AES-256
AES256_KEY = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
AES256_PT  = 0x00112233445566778899aabbccddeeff
AES256_CT  = 0x8ea2b7ca516745bfeafc49904b496089

# NIST AESAVS — additional AES-256 vectors (GFSbox)
AESAVS_VECTORS = [
    # (key, plaintext, ciphertext)
    (
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x014730f80ac625fe84f026c60bfd547d,
        0x5c9d844ed46f9885085e5d6a4f94c7d7,
    ),
    (
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0b24af36193ce4665f2825d7b4749c98,
        0xa9ff75bd7cf6613d3731c77c3b6d0c04,
    ),
    (
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x761c1fe41a18acf20d241650611d90f1,
        0x623a52fcea5d443e48d9181ab32c7421,
    ),
]


async def reset_dut(dut):
    """Apply reset sequence."""
    clock = Clock(dut.clk, 10, units="ns")
    cocotb.start_soon(clock.start())
    dut.rst_n.value = 0
    dut.load.value  = 0
    await ClockCycles(dut.clk, 4)
    dut.rst_n.value = 1
    await RisingEdge(dut.clk)


async def aes_encrypt(dut, key: int, plaintext: int) -> int:
    """Drive AES core and wait for result."""
    dut.key.value       = key
    dut.plaintext.value = plaintext
    dut.load.value      = 1
    await RisingEdge(dut.clk)
    dut.load.value = 0

    for _ in range(100):
        await RisingEdge(dut.clk)
        if int(dut.done.value) == 1:
            return int(dut.ciphertext.value)

    raise cocotb.result.TestFailure("AES timeout: done never asserted")


@cocotb.test()
async def test_fips197_appendix_c3(dut):
    """NIST FIPS 197 Appendix C.3 — AES-256 official test vector."""
    await reset_dut(dut)

    ct = await aes_encrypt(dut, AES256_KEY, AES256_PT)
    dut._log.info(f"CT got: 0x{ct:032x}")
    dut._log.info(f"CT exp: 0x{AES256_CT:032x}")

    assert ct == AES256_CT, (
        f"FIPS 197 AES-256 mismatch\n"
        f"  got 0x{ct:032x}\n"
        f"  exp 0x{AES256_CT:032x}"
    )
    dut._log.info("✓ FIPS 197 Appendix C.3 AES-256 PASSED")


@cocotb.test()
async def test_aesavs_gfsbox(dut):
    """NIST AESAVS GFSbox vectors for AES-256."""
    await reset_dut(dut)

    for i, (key, pt, expected_ct) in enumerate(AESAVS_VECTORS):
        await ClockCycles(dut.clk, 2)   # idle gap between operations
        ct = await aes_encrypt(dut, key, pt)
        assert ct == expected_ct, (
            f"AESAVS[{i}] mismatch\n"
            f"  key 0x{key:064x}\n"
            f"  pt  0x{pt:032x}\n"
            f"  got 0x{ct:032x}\n"
            f"  exp 0x{expected_ct:032x}"
        )
        dut._log.info(f"✓ AESAVS vector [{i}] PASSED")

    dut._log.info("✓ All NIST AESAVS GFSbox vectors PASSED")


@cocotb.test()
async def test_back_to_back(dut):
    """Run 8 consecutive AES operations to check no state leakage."""
    await reset_dut(dut)

    # Encrypt the FIPS197 vector 8 times back to back
    for i in range(8):
        await ClockCycles(dut.clk, 1)
        ct = await aes_encrypt(dut, AES256_KEY, AES256_PT)
        assert ct == AES256_CT, (
            f"Back-to-back iteration {i} failed: got 0x{ct:032x}"
        )
        dut._log.info(f"✓ Back-to-back [{i}] PASSED")

    dut._log.info("✓ 8× back-to-back AES-256 operations PASSED (no state leakage)")


@cocotb.test()
async def test_s_box_known_values(dut):
    """Verify known AES S-Box output via all-zero key encrypt."""
    await reset_dut(dut)

    # AES-256 encrypt of all-zeros with all-zeros key
    # Known result from NIST
    key_zero = 0x0000000000000000000000000000000000000000000000000000000000000000
    pt_zero  = 0x00000000000000000000000000000000
    # Expected from pycryptodome: AES(key=0*32, mode=ECB).encrypt(b'\x00'*16)
    expected = 0xdc95c078a2408989ad48a21492842087

    ct = await aes_encrypt(dut, key_zero, pt_zero)
    assert ct == expected, (
        f"Zero-key zero-PT mismatch: got 0x{ct:032x}, exp 0x{expected:032x}"
    )
    dut._log.info("✓ Zero-key zero-PT AES-256 test PASSED")


@cocotb.test()
async def test_all_ones_key(dut):
    """AES-256 with all-0xFF key."""
    await reset_dut(dut)

    key_ones = (1 << 256) - 1   # 0xFF * 32
    pt_zero  = 0x00000000000000000000000000000000
    # Verify determinism: run twice, must get same result
    ct1 = await aes_encrypt(dut, key_ones, pt_zero)
    await ClockCycles(dut.clk, 2)
    ct2 = await aes_encrypt(dut, key_ones, pt_zero)

    assert ct1 == ct2, f"Determinism failure: 0x{ct1:032x} ≠ 0x{ct2:032x}"
    assert ct1 != 0,   "All-zeros output from all-ones key is suspicious"
    dut._log.info(f"✓ All-0xFF key: CT = 0x{ct1:032x} (deterministic) PASSED")
