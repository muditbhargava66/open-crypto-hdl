"""
test_chacha20.py — cocotb testbench for chacha20_core.v
Uses official RFC 8439 §A.1 test vectors.

Requirements:
    pip install cocotb cocotb-test pycocotb

Run:
    make sim-chacha20
"""

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge, ClockCycles
import struct

# ── RFC 8439 §A.1 Test Vector ─────────────────────────────────────────────────
# key = 0x00..0x1f
RFC_KEY   = bytes(range(32))
RFC_NONCE = bytes([0x00,0x00,0x00,0x09,
                   0x00,0x00,0x00,0x4a,
                   0x00,0x00,0x00,0x00])
RFC_COUNTER = 1

# Expected first 4 words of keystream (from RFC 8439 §A.1)
RFC_EXPECTED_KS_WORDS = [
    0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3
]

def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, 'big')

def pack_key(key_bytes: bytes) -> int:
    """Pack 32-byte key into 256-bit integer (big-endian)."""
    return int.from_bytes(key_bytes, 'big')

def pack_nonce(nonce_bytes: bytes) -> int:
    """Pack 12-byte nonce into 96-bit integer."""
    return int.from_bytes(nonce_bytes, 'big')

@cocotb.test()
async def test_rfc8439_vector(dut):
    """Test ChaCha20 against RFC 8439 §A.1 test vector."""
    # Start clock
    clock = Clock(dut.clk, 10, units="ns")  # 100 MHz
    cocotb.start_soon(clock.start())

    # Reset
    dut.rst_n.value = 0
    dut.valid_in.value = 0
    await ClockCycles(dut.clk, 3)
    dut.rst_n.value = 1
    await RisingEdge(dut.clk)

    # Apply test vector
    dut.key.value     = pack_key(RFC_KEY)
    dut.nonce.value   = pack_nonce(RFC_NONCE)
    dut.counter.value = RFC_COUNTER
    dut.valid_in.value = 1
    await RisingEdge(dut.clk)
    dut.valid_in.value = 0

    # Wait for valid_out
    timeout = 200
    for _ in range(timeout):
        await RisingEdge(dut.clk)
        if dut.valid_out.value == 1:
            break
    else:
        raise cocotb.result.TestFailure("Timeout: valid_out never asserted")

    # Capture keystream
    ks_int = int(dut.keystream.value)
    ks_bytes = ks_int.to_bytes(64, 'big')

    # Extract words in little-endian (ChaCha20 output is LE)
    ks_words = list(struct.unpack('<16I', ks_bytes))

    dut._log.info(f"Keystream word[0] = 0x{ks_words[0]:08x} (expect 0x{RFC_EXPECTED_KS_WORDS[0]:08x})")
    dut._log.info(f"Keystream word[1] = 0x{ks_words[1]:08x} (expect 0x{RFC_EXPECTED_KS_WORDS[1]:08x})")
    dut._log.info(f"Keystream word[2] = 0x{ks_words[2]:08x} (expect 0x{RFC_EXPECTED_KS_WORDS[2]:08x})")
    dut._log.info(f"Keystream word[3] = 0x{ks_words[3]:08x} (expect 0x{RFC_EXPECTED_KS_WORDS[3]:08x})")

    for i, (got, exp) in enumerate(zip(ks_words[:4], RFC_EXPECTED_KS_WORDS)):
        assert got == exp, (
            f"Keystream mismatch at word {i}: "
            f"got 0x{got:08x}, expected 0x{exp:08x}"
        )

    dut._log.info("✓ RFC 8439 §A.1 test vector PASSED")


@cocotb.test()
async def test_consecutive_blocks(dut):
    """Verify counter increments produce different keystreams."""
    clock = Clock(dut.clk, 10, units="ns")
    cocotb.start_soon(clock.start())

    dut.rst_n.value = 0
    await ClockCycles(dut.clk, 3)
    dut.rst_n.value = 1

    results = []
    for ctr in range(4):
        dut.key.value     = pack_key(RFC_KEY)
        dut.nonce.value   = pack_nonce(RFC_NONCE)
        dut.counter.value = ctr
        dut.valid_in.value = 1
        await RisingEdge(dut.clk)
        dut.valid_in.value = 0

        for _ in range(200):
            await RisingEdge(dut.clk)
            if dut.valid_out.value == 1:
                results.append(int(dut.keystream.value))
                break

    # All keystreams must be unique
    assert len(set(results)) == 4, "Counter-distinct blocks should produce unique keystreams"
    dut._log.info("✓ Consecutive counter blocks are all unique — PASSED")


@cocotb.test()
async def test_zero_key_nonce(dut):
    """Smoke test: zero key and nonce should not hang."""
    clock = Clock(dut.clk, 10, units="ns")
    cocotb.start_soon(clock.start())

    dut.rst_n.value = 0
    await ClockCycles(dut.clk, 3)
    dut.rst_n.value = 1

    dut.key.value     = 0
    dut.nonce.value   = 0
    dut.counter.value = 0
    dut.valid_in.value = 1
    await RisingEdge(dut.clk)
    dut.valid_in.value = 0

    for _ in range(200):
        await RisingEdge(dut.clk)
        if dut.valid_out.value == 1:
            ks = int(dut.keystream.value)
            assert ks != 0, "Keystream for zero inputs must not be zero"
            dut._log.info("✓ Zero-key zero-nonce test PASSED")
            return

    raise cocotb.result.TestFailure("Timeout waiting for keystream")
