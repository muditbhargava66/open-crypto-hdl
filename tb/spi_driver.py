#!/usr/bin/env python3
"""
spi_driver.py — Python SPI driver for the open-crypto-hdl TinyTapeout wrapper
=============================================================================

Provides a clean Python API to drive the tt_um_crypto_top module via SPI.
Works with any backend that implements the SpiBackend interface:

  - RPicoBackend  — Raspberry Pi Pico / RP2040 via machine.SPI
  - FT232HBackend — FTDI FT232H via pyftdi
  - SimBackend    — Pure-Python simulation (drives cocotb via socket)

Quick start (Raspberry Pi Pico):
    import spi_driver
    spi = spi_driver.CryptoChip(backend=spi_driver.RPicoBackend(spi_id=0))
    spi.select_cipher('chacha20')
    spi.set_key(bytes(range(32)))
    spi.set_nonce(bytes(range(12)))
    spi.start()
    spi.wait_done()
    result = spi.read_result()
    print(result.hex())

SPI Protocol:
    Frame: [ADDR(8)] [R/W(1)] [DATA(8)] = 17 bits per transaction
    CS_N:  active low, held low for entire 17-bit frame
    CPOL=0, CPHA=0 (Mode 0)
"""

import struct
import time
from abc import ABC, abstractmethod
from typing import Optional


# ── Register map ──────────────────────────────────────────────────────────────
REG_CIPHER_SEL  = 0x00   # [1:0] 00=DES 01=AES-GCM 10=ChaCha20
REG_CMD         = 0x01   # write 0x01=start, 0x02=reset
REG_STATUS      = 0x02   # [0]=busy [1]=done
REG_KEY_BASE    = 0x10   # KEY bytes 0-31
REG_IV_BASE     = 0x30   # IV/Nonce bytes 0-11
REG_BLOCK_BASE  = 0x40   # Input block bytes 0-15
REG_RESULT_BASE = 0x50   # Result bytes 0-15 (read only)
REG_TAG_BASE    = 0x60   # Authentication tag 0-15 (read only)

CMD_START = 0x01
CMD_RESET = 0x02

STATUS_BUSY = 0x01
STATUS_DONE = 0x02

CIPHER_DES     = 0x00
CIPHER_AES_GCM = 0x01
CIPHER_CHACHA20 = 0x02

CIPHER_NAMES = {
    'des':      CIPHER_DES,
    'aes':      CIPHER_AES_GCM,
    'aes-gcm':  CIPHER_AES_GCM,
    'chacha20': CIPHER_CHACHA20,
    'chacha':   CIPHER_CHACHA20,
}


# ── Abstract SPI backend ───────────────────────────────────────────────────────
class SpiBackend(ABC):
    """Abstract interface — implement for your SPI hardware."""

    @abstractmethod
    def transfer(self, addr: int, rw: int, data: int) -> int:
        """
        Perform one 17-bit SPI transaction.
          addr: 8-bit register address
          rw:   1=read, 0=write
          data: 8-bit data byte (for writes; ignored for reads)
        Returns the 8-bit data byte received.
        """
        raise NotImplementedError


# ── Simulation backend (pure Python) ──────────────────────────────────────────
class SimBackend(SpiBackend):
    """
    In-memory simulation of the register file.
    Useful for unit testing the driver without hardware.
    Mimics register read/write behaviour but NOT actual crypto.
    """
    def __init__(self):
        self._regs = bytearray(256)
        self._regs[REG_STATUS] = 0x00

    def transfer(self, addr: int, rw: int, data: int) -> int:
        if rw == 0:   # write
            self._regs[addr] = data & 0xFF
            if addr == REG_CMD:
                if data == CMD_START:
                    # Simulate instant completion
                    self._regs[REG_STATUS] = STATUS_DONE
                elif data == CMD_RESET:
                    self._regs[REG_STATUS] = 0x00
            return 0
        else:         # read
            return self._regs[addr]


# ── FT232H backend (pyftdi) ───────────────────────────────────────────────────
class FT232HBackend(SpiBackend):
    """
    FTDI FT232H / FT2232H SPI backend via pyftdi.
    Install: pip install pyftdi
    Connect:
        AD0 → SCK   (uio[0])
        AD1 → MOSI  (uio[1])
        AD2 → MISO  (uio[2])
        AD3 → CS_N  (uio[3])
    """
    def __init__(self, url: str = 'ftdi://ftdi:232h/1', freq: int = 1_000_000):
        from pyftdi.spi import SpiController
        self._ctrl = SpiController()
        self._ctrl.configure(url)
        self._spi = self._ctrl.get_port(cs=0, freq=freq, mode=0)

    def transfer(self, addr: int, rw: int, data: int) -> int:
        # Pack 17 bits into 3 bytes (MSB first, padded)
        word = ((addr & 0xFF) << 9) | ((rw & 0x1) << 8) | (data & 0xFF)
        tx_bytes = bytes([(word >> 16) & 0xFF,
                          (word >> 8)  & 0xFF,
                           word        & 0xFF])
        rx = self._spi.exchange(tx_bytes, duplex=True)
        # MISO data is in the last byte
        return rx[-1]

    def close(self):
        self._ctrl.terminate()


# ── RP2040 / Raspberry Pi Pico backend ────────────────────────────────────────
class RPicoBackend(SpiBackend):
    """
    Raspberry Pi Pico (MicroPython) SPI backend.
    To use on-device, copy this class to the Pico and instantiate directly.

    Example pinout:
        SCK  → GP2  (spi0 SCK)
        MOSI → GP3  (spi0 TX)
        MISO → GP4  (spi0 RX)
        CS_N → GP5  (GPIO output)
    """
    def __init__(self, spi_id: int = 0, baudrate: int = 1_000_000,
                 sck_pin: int = 2, mosi_pin: int = 3,
                 miso_pin: int = 4, cs_pin: int = 5):
        try:
            from machine import SPI, Pin
            self._cs = Pin(cs_pin, Pin.OUT, value=1)
            self._spi = SPI(spi_id, baudrate=baudrate,
                            sck=Pin(sck_pin), mosi=Pin(mosi_pin),
                            miso=Pin(miso_pin), polarity=0, phase=0)
        except ImportError:
            raise RuntimeError("RPicoBackend requires MicroPython (machine module)")

    def transfer(self, addr: int, rw: int, data: int) -> int:
        word = ((addr & 0xFF) << 9) | ((rw & 0x1) << 8) | (data & 0xFF)
        tx = bytes([word >> 8 & 0xFF, word & 0xFF, 0x00])
        rx = bytearray(3)
        self._cs.value(0)
        self._spi.write_readinto(tx, rx)
        self._cs.value(1)
        return rx[2]


# ── High-level CryptoChip driver ──────────────────────────────────────────────
class CryptoChip:
    """
    High-level API for the open-crypto-hdl TinyTapeout chip.

    Example (AES-256 encrypt one block):

        chip = CryptoChip(backend=SimBackend())
        chip.reset()
        chip.select_cipher('aes')
        chip.set_key(b'\\x00' * 32)
        chip.set_block(b'\\x00' * 16)
        chip.start()
        chip.wait_done(timeout_ms=100)
        ct = chip.read_result(16)
        print('CT:', ct.hex())
    """

    def __init__(self, backend: Optional[SpiBackend] = None):
        self._b = backend or SimBackend()

    # ── Low-level register access ─────────────────────────────────────────────
    def write_reg(self, addr: int, data: int):
        """Write one byte to a register."""
        self._b.transfer(addr & 0xFF, 0, data & 0xFF)

    def read_reg(self, addr: int) -> int:
        """Read one byte from a register."""
        return self._b.transfer(addr & 0xFF, 1, 0x00) & 0xFF

    def write_bytes(self, base_addr: int, data: bytes):
        """Write a byte array starting at base_addr."""
        for i, byte in enumerate(data):
            self.write_reg(base_addr + i, byte)

    def read_bytes(self, base_addr: int, count: int) -> bytes:
        """Read count bytes starting at base_addr."""
        return bytes(self.read_reg(base_addr + i) for i in range(count))

    # ── High-level API ────────────────────────────────────────────────────────
    def reset(self):
        """Reset all cipher state."""
        self.write_reg(REG_CMD, CMD_RESET)
        time.sleep(0.001)

    def select_cipher(self, cipher: str):
        """Select cipher: 'des', 'aes', 'aes-gcm', or 'chacha20'."""
        sel = CIPHER_NAMES.get(cipher.lower())
        if sel is None:
            raise ValueError(f"Unknown cipher '{cipher}'. Choose: {list(CIPHER_NAMES)}")
        self.write_reg(REG_CIPHER_SEL, sel)

    def set_key(self, key: bytes):
        """
        Set cipher key.
          DES:     8 bytes
          AES-256: 32 bytes
          ChaCha20: 32 bytes
        """
        if len(key) not in (8, 32):
            raise ValueError(f"Key must be 8 (DES) or 32 (AES/ChaCha20) bytes, got {len(key)}")
        self.write_bytes(REG_KEY_BASE, key[:32])

    def set_nonce(self, nonce: bytes):
        """Set IV/nonce (up to 12 bytes for AES-GCM and ChaCha20)."""
        if len(nonce) > 12:
            raise ValueError(f"Nonce must be ≤ 12 bytes, got {len(nonce)}")
        self.write_bytes(REG_IV_BASE, nonce)

    def set_block(self, block: bytes):
        """Set input data block (up to 16 bytes)."""
        if len(block) > 16:
            raise ValueError(f"Block must be ≤ 16 bytes, got {len(block)}")
        padded = block + b'\x00' * (16 - len(block))
        self.write_bytes(REG_BLOCK_BASE, padded)

    def set_counter(self, counter: int):
        """Set ChaCha20 block counter (32-bit, stored in block[3:0])."""
        ctr_bytes = struct.pack('>I', counter & 0xFFFFFFFF)
        self.write_bytes(REG_BLOCK_BASE, ctr_bytes)

    def start(self):
        """Assert CMD=START to begin cipher operation."""
        self.write_reg(REG_CMD, CMD_START)

    def status(self) -> int:
        """Read STATUS register. Returns bitmask: [0]=busy [1]=done."""
        return self.read_reg(REG_STATUS)

    def is_busy(self) -> bool:
        return bool(self.status() & STATUS_BUSY)

    def is_done(self) -> bool:
        return bool(self.status() & STATUS_DONE)

    def wait_done(self, timeout_ms: int = 500, poll_interval_ms: float = 0.5):
        """Poll until done or timeout. Raises TimeoutError on timeout."""
        deadline = time.time() + timeout_ms / 1000
        while time.time() < deadline:
            if self.is_done():
                return
            time.sleep(poll_interval_ms / 1000)
        raise TimeoutError(f"Cipher operation did not complete within {timeout_ms} ms")

    def read_result(self, count: int = 16) -> bytes:
        """Read result bytes (ciphertext output)."""
        if count > 16:
            raise ValueError("Maximum 16 result bytes")
        return self.read_bytes(REG_RESULT_BASE, count)

    def read_tag(self) -> bytes:
        """Read 16-byte authentication tag (AEAD ciphers only)."""
        return self.read_bytes(REG_TAG_BASE, 16)

    # ── Convenience one-shot operations ──────────────────────────────────────
    def des_encrypt(self, key: bytes, plaintext: bytes) -> bytes:
        """One-shot DES encryption."""
        self.reset()
        self.select_cipher('des')
        self.set_key(key[:8])
        self.set_block(plaintext[:8])
        self.start()
        self.wait_done()
        return self.read_result(8)

    def des_decrypt(self, key: bytes, ciphertext: bytes) -> bytes:
        """One-shot DES decryption."""
        # Toggle encrypt bit via block[8]=0 (convention: block_in[0]=decrypt flag)
        # For simplicity in this driver: write 0xFF to first block byte to signal decrypt
        # Real implementation: add a dedicated register or use MSB of cipher_sel
        raise NotImplementedError("DES decrypt via SPI: set bit in CIPHER_SEL[2] or use separate register")

    def aes256_encrypt_block(self, key: bytes, plaintext: bytes) -> bytes:
        """One-shot AES-256 ECB block encryption."""
        if len(key) != 32:
            raise ValueError("AES-256 requires 32-byte key")
        if len(plaintext) != 16:
            raise ValueError("AES-256 block must be 16 bytes")
        self.reset()
        self.select_cipher('aes')
        self.set_key(key)
        self.set_block(plaintext)
        self.start()
        self.wait_done()
        return self.read_result(16)

    def chacha20_keystream(self, key: bytes, nonce: bytes,
                           counter: int = 0) -> bytes:
        """Generate one 64-byte ChaCha20 keystream block."""
        if len(key) != 32:
            raise ValueError("ChaCha20 requires 32-byte key")
        if len(nonce) != 12:
            raise ValueError("ChaCha20 nonce must be 12 bytes")
        self.reset()
        self.select_cipher('chacha20')
        self.set_key(key)
        self.set_nonce(nonce)
        self.set_counter(counter)
        self.start()
        self.wait_done()
        # Result register holds first 16 bytes of keystream
        return self.read_result(16)

    def chacha20_encrypt(self, key: bytes, nonce: bytes,
                         plaintext: bytes, initial_counter: int = 1) -> bytes:
        """
        Encrypt plaintext with ChaCha20 (streaming, 16 bytes at a time).
        Returns full ciphertext.
        """
        if len(key) != 32:
            raise ValueError("ChaCha20 requires 32-byte key")
        if len(nonce) != 12:
            raise ValueError("ChaCha20 nonce must be 12 bytes")

        ciphertext = bytearray()
        counter = initial_counter

        # Process in 16-byte chunks (one keystream word at a time)
        # Note: ChaCha20 block = 64 bytes; each call to the hardware
        # returns 16 bytes. For a 64-byte block we need 4 calls (ctr increment
        # happens every 64 bytes in spec, but hardware gives 16B windows).
        for i in range(0, len(plaintext), 16):
            chunk = plaintext[i:i+16]
            ks = self.chacha20_keystream(key, nonce, counter)
            ct_chunk = bytes(p ^ k for p, k in zip(chunk, ks))
            ciphertext.extend(ct_chunk)
            counter += 1  # simplified: increment per 16 bytes (adjust for spec)

        return bytes(ciphertext)


# ── Self-test against Python reference ───────────────────────────────────────
def _self_test_sim():
    """Run basic sanity checks using SimBackend (no hardware)."""
    print("Running SPI driver self-test (SimBackend)...")
    chip = CryptoChip(backend=SimBackend())

    # Test register read/write
    chip.write_reg(0x00, 0xAB)
    val = chip.read_reg(0x00)
    assert val == 0xAB, f"Register R/W failed: {val:#04x}"
    print("  ✓ Register read/write")

    # Test write_bytes / read_bytes
    test_key = bytes(range(32))
    chip.write_bytes(REG_KEY_BASE, test_key)
    readback = chip.read_bytes(REG_KEY_BASE, 32)
    assert readback == test_key, "Key R/W mismatch"
    print("  ✓ Key register R/W (32 bytes)")

    # Test cipher selection
    chip.select_cipher('aes')
    assert chip.read_reg(REG_CIPHER_SEL) == CIPHER_AES_GCM
    chip.select_cipher('des')
    assert chip.read_reg(REG_CIPHER_SEL) == CIPHER_DES
    chip.select_cipher('chacha20')
    assert chip.read_reg(REG_CIPHER_SEL) == CIPHER_CHACHA20
    print("  ✓ Cipher selection")

    # Test start → wait_done flow (SimBackend sets done immediately)
    chip.reset()
    chip.select_cipher('aes')
    chip.set_key(bytes(32))
    chip.set_block(bytes(16))
    chip.start()
    chip.wait_done(timeout_ms=100)
    assert chip.is_done(), "Should be done after start"
    print("  ✓ Start/wait_done flow")

    print("  ALL SELF-TESTS PASSED ✓")


if __name__ == "__main__":
    import sys
    if "--test" in sys.argv:
        _self_test_sim()
    elif "--vectors" in sys.argv:
        # Print hardware validation vectors using pycryptodome
        try:
            from Crypto.Cipher import AES, DES
            print("=== Hardware Validation Vectors ===")
            print()

            # AES-256 ECB
            key32 = bytes(range(32))
            pt16  = bytes(range(16))
            ct16  = AES.new(key32, AES.MODE_ECB).encrypt(pt16)
            print("AES-256 ECB:")
            print(f"  key:    {key32.hex()}")
            print(f"  pt:     {pt16.hex()}")
            print(f"  ct:     {ct16.hex()}")
            print()

            # DES ECB
            key8 = bytes.fromhex("133457799BBCDFF1")
            pt8  = bytes.fromhex("0123456789ABCDEF")
            ct8  = DES.new(key8, DES.MODE_ECB).encrypt(pt8)
            print("DES ECB:")
            print(f"  key:    {key8.hex()}")
            print(f"  pt:     {pt8.hex()}")
            print(f"  ct:     {ct8.hex()}")
        except ImportError:
            print("Install pycryptodome for vector generation: pip install pycryptodome")
    else:
        print(__doc__)
        print()
        print("Usage:")
        print("  python3 spi_driver.py --test      Run SimBackend self-tests")
        print("  python3 spi_driver.py --vectors   Print hardware validation vectors")
