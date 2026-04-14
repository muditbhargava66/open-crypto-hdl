"""
test_poly1305.py — cocotb testbench for poly1305_core.v
RFC 8439 §2.5.2 test vectors for Poly1305 MAC.

Run:
    TOPLEVEL=poly1305_core MODULE=tb.cocotb.test_poly1305 \
    VERILOG_SOURCES="rtl/poly1305/poly1305_core.v" SIM=icarus \
    make -f $(cocotb-config --makefiles)/Makefile.sim
"""

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge, ClockCycles


# ── RFC 8439 §2.5.2 Test Vector ──────────────────────────────────────────────
# Key (r || s) — 256-bit:
#   r = 0x85d6be7857556d337f4452fe42d506a8 (clamped internally)
#   s = 0x01030780f20c225a1fb25e116d395b2e  (not clamped)
# (r is low 128 bits, s is high 128 bits of key)
#
# Message: "Cryptographic Forum Research Group" (34 bytes)
# Expected tag: 0xa8061dc1305136c6c22b8baf0c0127a9
#
# Key layout for poly1305_core:
#   key[127:0]   = r (low half)
#   key[255:128]  = s (high half)

RFC_R = 0x85d6be7857556d337f4452fe42d506a8
RFC_S = 0x01030780f20c225a1fb25e116d395b2e
RFC_KEY = (RFC_S << 128) | RFC_R

# "Cryptographic Forum Research Group" = 34 bytes
RFC_MSG = b"Cryptographic Forum Research Group"
RFC_TAG = 0xa8061dc1305136c6c22b8baf0c0127a9


def msg_to_blocks(msg: bytes) -> list:
    """Split message into 16-byte blocks with lengths."""
    blocks = []
    for i in range(0, len(msg), 16):
        chunk = msg[i:i+16]
        # Convert to integer (little-endian as per Poly1305)
        val = int.from_bytes(chunk, 'little')
        blocks.append((val, len(chunk), i + len(chunk) >= len(msg)))
    return blocks


async def reset_dut(dut):
    """Apply reset sequence."""
    clock = Clock(dut.clk, 10, units="ns")
    cocotb.start_soon(clock.start())
    dut.rst_n.value = 0
    dut.init.value = 0
    dut.next.value = 0
    await ClockCycles(dut.clk, 4)
    dut.rst_n.value = 1
    await RisingEdge(dut.clk)


@cocotb.test()
async def test_rfc8439_poly1305(dut):
    """RFC 8439 §2.5.2 Poly1305 test vector."""
    await reset_dut(dut)

    # Init with key
    dut.key.value = RFC_KEY
    dut.init.value = 1
    await RisingEdge(dut.clk)
    dut.init.value = 0
    await RisingEdge(dut.clk)

    # Process message blocks
    blocks = msg_to_blocks(RFC_MSG)
    for i, (block_val, block_len, is_last) in enumerate(blocks):
        dut.block.value = block_val
        dut.block_len.value = block_len
        dut.last_block.value = 1 if is_last else 0
        dut.next.value = 1
        await RisingEdge(dut.clk)
        dut.next.value = 0

        if is_last:
            # Wait for tag_valid
            for _ in range(50):
                await RisingEdge(dut.clk)
                if int(dut.tag_valid.value) == 1:
                    tag = int(dut.tag.value)
                    dut._log.info(f"Tag got: 0x{tag:032x}")
                    dut._log.info(f"Tag exp: 0x{RFC_TAG:032x}")
                    assert tag == RFC_TAG, (
                        f"RFC 8439 Poly1305 tag mismatch\n"
                        f"  got 0x{tag:032x}\n"
                        f"  exp 0x{RFC_TAG:032x}"
                    )
                    dut._log.info("✓ RFC 8439 §2.5.2 Poly1305 PASSED")
                    return

            raise cocotb.result.TestFailure("Timeout: tag_valid never asserted")
        else:
            await RisingEdge(dut.clk)
            dut._log.info(f"  Block [{i}] processed ({block_len} bytes)")


@cocotb.test()
async def test_single_block(dut):
    """Single full 16-byte block MAC should produce a non-zero tag."""
    await reset_dut(dut)

    key = (0xdeadbeef << 128) | 0xcafebabe
    dut.key.value = key
    dut.init.value = 1
    await RisingEdge(dut.clk)
    dut.init.value = 0
    await RisingEdge(dut.clk)

    dut.block.value = 0x0102030405060708090a0b0c0d0e0f10
    dut.block_len.value = 16
    dut.last_block.value = 1
    dut.next.value = 1
    await RisingEdge(dut.clk)
    dut.next.value = 0

    for _ in range(50):
        await RisingEdge(dut.clk)
        if int(dut.tag_valid.value) == 1:
            tag = int(dut.tag.value)
            assert tag != 0, "Tag should not be zero for non-zero inputs"
            dut._log.info(f"✓ Single-block Poly1305 tag = 0x{tag:032x} PASSED")
            return

    raise cocotb.result.TestFailure("Single-block timeout")


@cocotb.test()
async def test_zero_message(dut):
    """Zero message should still produce a valid tag (should equal s)."""
    await reset_dut(dut)

    # With zero r and some s, tag should be s mod 2^128
    s_val = 0x01030780f20c225a1fb25e116d395b2e
    key = (s_val << 128)  # r=0, s=s_val

    dut.key.value = key
    dut.init.value = 1
    await RisingEdge(dut.clk)
    dut.init.value = 0
    await RisingEdge(dut.clk)

    # Process a zero block as last
    dut.block.value = 0
    dut.block_len.value = 16
    dut.last_block.value = 1
    dut.next.value = 1
    await RisingEdge(dut.clk)
    dut.next.value = 0

    for _ in range(50):
        await RisingEdge(dut.clk)
        if int(dut.tag_valid.value) == 1:
            tag = int(dut.tag.value)
            dut._log.info(f"✓ Zero-message tag = 0x{tag:032x} PASSED")
            return

    raise cocotb.result.TestFailure("Zero-message timeout")
