"""
test_des.py — cocotb testbench for des_core.v
Uses NIST Known-Answer Test (KAT) vectors from FIPS 81 / DES algorithm.

Run:
    make sim-des
"""

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge, ClockCycles

# ── NIST DES Test Vectors ─────────────────────────────────────────────────────
# Format: (key_hex, plaintext_hex, ciphertext_hex)
DES_VECTORS = [
    # NIST SP 800-20 Table A.1 — Variable Plaintext Known Answer Test
    ("0101010101010101", "8000000000000000", "95f8a5e5dd31d900"),
    ("0101010101010101", "4000000000000000", "dd7f121ca5015619"),
    ("0101010101010101", "2000000000000000", "2e8653104f3834ea"),
    ("0101010101010101", "0000000000000001", "166b40b44aba4bd6"),
    # Variable Key Known Answer Test
    ("8001010101010101", "0000000000000000", "95a8d72813daa94d"),
    ("4001010101010101", "0000000000000000", "0eec1487dd8c26d5"),
    ("2001010101010101", "0000000000000000", "7ad16ffb79c45926"),
    # Classic test vector
    ("133457799BBCDFF1", "0123456789ABCDEF", "85E813540F0AB405"),
]

@cocotb.test()
async def test_des_encrypt_vectors(dut):
    """Test DES encryption against NIST KAT vectors."""
    clock = Clock(dut.clk, 10, unit="ns")
    cocotb.start_soon(clock.start())

    dut.rst_n.value = 0
    await ClockCycles(dut.clk, 3)
    dut.rst_n.value = 1

    failures = []
    for key_hex, pt_hex, ct_hex in DES_VECTORS:
        key_val = int(key_hex, 16)
        pt_val  = int(pt_hex, 16)
        ct_exp  = int(ct_hex, 16)

        dut.key.value     = key_val
        dut.block.value   = pt_val
        dut.encrypt.value = 1
        dut.load.value    = 1
        await RisingEdge(dut.clk)
        dut.load.value = 0

        timeout = 100
        for _ in range(timeout):
            await RisingEdge(dut.clk)
            if dut.done.value == 1:
                break
        else:
            failures.append(f"TIMEOUT for key={key_hex} pt={pt_hex}")
            continue

        got = int(dut.result.value)
        if got != ct_exp:
            failures.append(
                f"ENCRYPT MISMATCH\n"
                f"  key={key_hex} pt={pt_hex}\n"
                f"  got=0x{got:016x}\n"
                f"  exp=0x{ct_exp:016x}"
            )
        else:
            dut._log.info(f"✓ key={key_hex} pt={pt_hex} → {ct_hex}")

        await ClockCycles(dut.clk, 2)  # idle gap

    if failures:
        assert False,("\n".join(failures))
    dut._log.info(f"✓ All {len(DES_VECTORS)} DES encrypt vectors PASSED")


@cocotb.test()
async def test_des_decrypt_roundtrip(dut):
    """Encrypt then decrypt — must recover original plaintext."""
    clock = Clock(dut.clk, 10, unit="ns")
    cocotb.start_soon(clock.start())

    dut.rst_n.value = 0
    await ClockCycles(dut.clk, 3)
    dut.rst_n.value = 1

    key_val = 0x133457799BBCDFF1
    pt_val  = 0x0123456789ABCDEF

    # Encrypt
    dut.key.value     = key_val
    dut.block.value   = pt_val
    dut.encrypt.value = 1
    dut.load.value    = 1
    await RisingEdge(dut.clk)
    dut.load.value = 0

    for _ in range(100):
        await RisingEdge(dut.clk)
        if dut.done.value == 1:
            ciphertext = int(dut.result.value)
            break
    else:
        assert False,("Encrypt timeout")

    await ClockCycles(dut.clk, 2)

    # Decrypt
    dut.block.value   = ciphertext
    dut.encrypt.value = 0
    dut.load.value    = 1
    await RisingEdge(dut.clk)
    dut.load.value = 0

    for _ in range(100):
        await RisingEdge(dut.clk)
        if dut.done.value == 1:
            recovered = int(dut.result.value)
            break
    else:
        assert False,("Decrypt timeout")

    assert recovered == pt_val, (
        f"Roundtrip mismatch: "
        f"original=0x{pt_val:016x} "
        f"ciphertext=0x{ciphertext:016x} "
        f"recovered=0x{recovered:016x}"
    )
    dut._log.info(f"✓ DES encrypt/decrypt roundtrip PASSED")
    dut._log.info(f"  PT=0x{pt_val:016x} → CT=0x{ciphertext:016x} → PT=0x{recovered:016x}")
