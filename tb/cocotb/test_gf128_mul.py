"""
test_gf128_mul.py — cocotb testbench for gf128_mul.v
GF(2^128) multiplier unit tests with NIST SP 800-38D vectors.

Run:
    TOPLEVEL=gf128_mul MODULE=tb.cocotb.test_gf128_mul \
    VERILOG_SOURCES="rtl/gcm/gf128_mul.v" SIM=icarus \
    make -f $(cocotb-config --makefiles)/Makefile.sim
"""

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge, ClockCycles


# ── NIST SP 800-38D Test Vectors ──────────────────────────────────────────────
# GF(2^128) multiply: Z = X * Y mod p(x)
# p(x) = x^128 + x^7 + x^2 + x + 1
#
# Test Case 2 from NIST SP 800-38D (H and first block for AES-GCM):
#   H  = 0x66e94bd4ef8a2c3b884cfa59ca342b2e  (AES_K(0) for key=0)
#   X  = 0x00000000000000000000000000000000  (zero block)
#   Result = 0  (anything * 0 = 0 in GF)
#
# Additional algebraic tests:
#   X * 1 = X  (multiplicative identity, but note GCM bit ordering)
GF128_VECTORS = [
    # (X, Y, expected_product)
    # Identity: X * 0 = 0
    (
        0x66e94bd4ef8a2c3b884cfa59ca342b2e,
        0x00000000000000000000000000000000,
        0x00000000000000000000000000000000,
    ),
    # Zero * anything = 0
    (
        0x00000000000000000000000000000000,
        0xabcdef0123456789abcdef0123456789,
        0x00000000000000000000000000000000,
    ),
    # Known GCM multiply result (from pycryptodome / OpenSSL verification)
    # H = 0x66e94bd4ef8a2c3b884cfa59ca342b2e
    # X = 0x0388dace60b6a392f328c2b971b2fe78
    # Result verified with GCM reference implementation
    (
        0x66e94bd4ef8a2c3b884cfa59ca342b2e,
        0x0388dace60b6a392f328c2b971b2fe78,
        0x5e2ec746917062882c85b0685353deb7,
    ),
]


async def reset_dut(dut):
    """Apply reset sequence."""
    clock = Clock(dut.clk, 10, unit="ns")
    cocotb.start_soon(clock.start())
    dut.rst_n.value = 0
    dut.start.value = 0
    await ClockCycles(dut.clk, 4)
    dut.rst_n.value = 1
    await RisingEdge(dut.clk)


async def gf128_multiply(dut, x: int, y: int) -> int:
    """Drive GF128 multiply and wait for result."""
    dut.x.value = x
    dut.y.value = y
    dut.start.value = 1
    await RisingEdge(dut.clk)
    dut.start.value = 0

    for _ in range(200):
        await RisingEdge(dut.clk)
        if int(dut.valid.value) == 1:
            return int(dut.result.value)

    assert False,("GF128 multiply timeout: valid never asserted")


@cocotb.test()
async def test_zero_multiply(dut):
    """Anything multiplied by zero should be zero in GF(2^128)."""
    await reset_dut(dut)

    x = 0x66e94bd4ef8a2c3b884cfa59ca342b2e
    result = await gf128_multiply(dut, x, 0)
    assert result == 0, f"X * 0 should be 0, got 0x{result:032x}"
    dut._log.info("✓ GF128: X * 0 = 0 PASSED")


@cocotb.test()
async def test_commutative(dut):
    """GF(2^128) multiply is commutative: X*Y == Y*X."""
    await reset_dut(dut)

    x = 0x66e94bd4ef8a2c3b884cfa59ca342b2e
    y = 0x0388dace60b6a392f328c2b971b2fe78

    r1 = await gf128_multiply(dut, x, y)
    await ClockCycles(dut.clk, 2)
    r2 = await gf128_multiply(dut, y, x)

    assert r1 == r2, f"Commutativity failed: 0x{r1:032x} != 0x{r2:032x}"
    dut._log.info(f"✓ GF128: X*Y == Y*X = 0x{r1:032x} PASSED")


@cocotb.test()
async def test_known_vectors(dut):
    """Test GF(2^128) multiply against known vectors."""
    await reset_dut(dut)

    for i, (x, y, expected) in enumerate(GF128_VECTORS):
        await ClockCycles(dut.clk, 2)
        result = await gf128_multiply(dut, x, y)
        assert result == expected, (
            f"GF128 vector [{i}] mismatch\n"
            f"  X   = 0x{x:032x}\n"
            f"  Y   = 0x{y:032x}\n"
            f"  got = 0x{result:032x}\n"
            f"  exp = 0x{expected:032x}"
        )
        dut._log.info(f"✓ GF128 vector [{i}] PASSED")

    dut._log.info(f"✓ All {len(GF128_VECTORS)} GF128 vectors PASSED")


@cocotb.test()
async def test_determinism(dut):
    """Same inputs must produce same output across multiple runs."""
    await reset_dut(dut)

    x = 0x0388dace60b6a392f328c2b971b2fe78
    y = 0x66e94bd4ef8a2c3b884cfa59ca342b2e

    r1 = await gf128_multiply(dut, x, y)
    await ClockCycles(dut.clk, 2)
    r2 = await gf128_multiply(dut, x, y)

    assert r1 == r2, f"Determinism failure: 0x{r1:032x} != 0x{r2:032x}"
    assert r1 != 0, "Non-zero inputs should produce non-zero result"
    dut._log.info(f"✓ GF128 determinism PASSED (result = 0x{r1:032x})")
