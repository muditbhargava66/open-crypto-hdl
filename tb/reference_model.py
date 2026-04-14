#!/usr/bin/env python3
"""
reference_model.py — Software reference implementations for cross-validation
Generates test vectors that can be used to verify RTL outputs.

Dependencies:
    pip install pycryptodome

Usage:
    python3 tb/reference_model.py          # Print all vectors
    python3 tb/reference_model.py --json   # Output JSON for cocotb use
    python3 tb/reference_model.py --sv     # Output SystemVerilog parameter file
"""

import argparse
import json
import struct
import sys
from typing import Optional

# ── ChaCha20 reference (pure Python, no dependencies) ────────────────────────

def _rotl32(v: int, n: int) -> int:
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF

def _quarter_round(a, b, c, d):
    a = (a + b) & 0xFFFFFFFF; d ^= a; d = _rotl32(d, 16)
    c = (c + d) & 0xFFFFFFFF; b ^= c; b = _rotl32(b, 12)
    a = (a + b) & 0xFFFFFFFF; d ^= a; d = _rotl32(d,  8)
    c = (c + d) & 0xFFFFFFFF; b ^= c; b = _rotl32(b,  7)
    return a, b, c, d

def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """Generate one 64-byte ChaCha20 keystream block (RFC 8439)."""
    assert len(key)   == 32
    assert len(nonce) == 12

    # Initial state
    constants = struct.unpack('<4I', b'expa' + b'nd 3' + b'2-by' + b'te k')
    key_words  = struct.unpack('<8I', key)
    nonce_words = struct.unpack('<3I', nonce)

    state = list(constants) + list(key_words) + [counter] + list(nonce_words)
    working = state[:]

    for _ in range(10):  # 10 double-rounds = 20 rounds
        # Column rounds
        working[0],working[4],working[ 8],working[12] = _quarter_round(working[0],working[4],working[ 8],working[12])
        working[1],working[5],working[ 9],working[13] = _quarter_round(working[1],working[5],working[ 9],working[13])
        working[2],working[6],working[10],working[14] = _quarter_round(working[2],working[6],working[10],working[14])
        working[3],working[7],working[11],working[15] = _quarter_round(working[3],working[7],working[11],working[15])
        # Diagonal rounds
        working[0],working[5],working[10],working[15] = _quarter_round(working[0],working[5],working[10],working[15])
        working[1],working[6],working[11],working[12] = _quarter_round(working[1],working[6],working[11],working[12])
        working[2],working[7],working[ 8],working[13] = _quarter_round(working[2],working[7],working[ 8],working[13])
        working[3],working[4],working[ 9],working[14] = _quarter_round(working[3],working[4],working[ 9],working[14])

    output = [(working[i] + state[i]) & 0xFFFFFFFF for i in range(16)]
    return struct.pack('<16I', *output)


def chacha20_encrypt(key: bytes, nonce: bytes, plaintext: bytes,
                     initial_counter: int = 1) -> bytes:
    """Encrypt plaintext with ChaCha20."""
    result = bytearray()
    counter = initial_counter
    for i in range(0, len(plaintext), 64):
        ks = chacha20_block(key, counter, nonce)
        chunk = plaintext[i:i+64]
        result.extend(a ^ b for a, b in zip(chunk, ks))
        counter += 1
    return bytes(result)


# ── Poly1305 reference ────────────────────────────────────────────────────────

def poly1305_mac(key: bytes, msg: bytes) -> bytes:
    """Poly1305 MAC (RFC 8439)."""
    assert len(key) == 32
    r = int.from_bytes(key[:16], 'little')
    r &= 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF  # clamp
    s = int.from_bytes(key[16:], 'little')

    P = (1 << 130) - 5
    acc = 0

    for i in range(0, len(msg), 16):
        block = msg[i:i+16]
        n = int.from_bytes(block, 'little') | (1 << (8 * len(block)))
        acc = (r * (acc + n)) % P

    tag = (acc + s) & ((1 << 128) - 1)
    return tag.to_bytes(16, 'little')


# ── AES-256 reference (using pycryptodome) ───────────────────────────────────

def aes256_ecb_encrypt(key: bytes, plaintext: bytes) -> bytes:
    try:
        from Crypto.Cipher import AES
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.encrypt(plaintext)
    except ImportError:
        print("WARNING: pycryptodome not installed. AES vectors unavailable.", file=sys.stderr)
        return b'\x00' * 16


def aes256_gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes,
                       aad: bytes = b'') -> tuple[bytes, bytes]:
    try:
        from Crypto.Cipher import AES
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        cipher.update(aad)
        ct, tag = cipher.encrypt_and_digest(plaintext)
        return ct, tag
    except ImportError:
        print("WARNING: pycryptodome not installed.", file=sys.stderr)
        return b'\x00' * len(plaintext), b'\x00' * 16


# ── DES reference (using pycryptodome) ───────────────────────────────────────

def des_ecb_encrypt(key: bytes, plaintext: bytes) -> bytes:
    try:
        from Crypto.Cipher import DES
        cipher = DES.new(key, DES.MODE_ECB)
        return cipher.encrypt(plaintext)
    except ImportError:
        print("WARNING: pycryptodome not installed. DES vectors unavailable.", file=sys.stderr)
        return b'\x00' * 8


# ── Test vector generation ────────────────────────────────────────────────────

def generate_chacha20_vectors() -> list[dict]:
    vectors = []

    # RFC 8439 §A.1 — Official test vector
    key   = bytes(range(32))
    nonce = bytes([0,0,0,9, 0,0,0,0x4a, 0,0,0,0])
    ks    = chacha20_block(key, 1, nonce)
    vectors.append({
        "name": "RFC8439-A1",
        "key":     key.hex(),
        "nonce":   nonce.hex(),
        "counter": 1,
        "keystream_hex": ks.hex(),
        "keystream_words_le": [
            struct.unpack_from('<I', ks, i*4)[0] for i in range(16)
        ],
    })

    # All-zeros
    ks0 = chacha20_block(b'\x00'*32, 0, b'\x00'*12)
    vectors.append({
        "name":    "ALL-ZEROS-CTR0",
        "key":     "00" * 32,
        "nonce":   "00" * 12,
        "counter": 0,
        "keystream_hex": ks0.hex(),
        "keystream_words_le": [
            struct.unpack_from('<I', ks0, i*4)[0] for i in range(16)
        ],
    })

    # All-zeros ctr=1
    ks1 = chacha20_block(b'\x00'*32, 1, b'\x00'*12)
    vectors.append({
        "name":    "ALL-ZEROS-CTR1",
        "key":     "00" * 32,
        "nonce":   "00" * 12,
        "counter": 1,
        "keystream_hex": ks1.hex(),
        "keystream_words_le": [
            struct.unpack_from('<I', ks1, i*4)[0] for i in range(16)
        ],
    })

    return vectors


def generate_des_vectors() -> list[dict]:
    vectors = []
    test_cases = [
        ("0101010101010101", "8000000000000000"),
        ("0101010101010101", "4000000000000000"),
        ("0101010101010101", "2000000000000000"),
        ("133457799BBCDFF1", "0123456789ABCDEF"),
        ("8001010101010101", "0000000000000000"),
    ]
    for key_hex, pt_hex in test_cases:
        key = bytes.fromhex(key_hex)
        pt  = bytes.fromhex(pt_hex)
        ct  = des_ecb_encrypt(key, pt)
        vectors.append({
            "key_hex": key_hex,
            "pt_hex":  pt_hex,
            "ct_hex":  ct.hex().upper(),
        })
    return vectors


def generate_aes256_vectors() -> list[dict]:
    vectors = []

    # FIPS 197 Appendix C.3
    key = bytes(range(32))
    pt  = bytes.fromhex("00112233445566778899aabbccddeeff")
    ct  = aes256_ecb_encrypt(key, pt)
    vectors.append({
        "name": "FIPS197-C3",
        "key_hex": key.hex(),
        "pt_hex":  pt.hex(),
        "ct_hex":  ct.hex(),
    })

    # Zero key, zero pt
    ct0 = aes256_ecb_encrypt(b'\x00'*32, b'\x00'*16)
    vectors.append({
        "name": "ZERO-KEY-ZERO-PT",
        "key_hex": "00" * 32,
        "pt_hex":  "00" * 16,
        "ct_hex":  ct0.hex(),
    })

    return vectors


def generate_aes_gcm_vectors() -> list[dict]:
    vectors = []

    key   = bytes(range(32))
    nonce = bytes(range(12))
    pt    = b"Hello, crypto!"
    aad   = b"Additional data"

    ct, tag = aes256_gcm_encrypt(key, nonce, pt, aad)
    vectors.append({
        "name":      "AES-256-GCM-basic",
        "key_hex":   key.hex(),
        "nonce_hex": nonce.hex(),
        "aad_hex":   aad.hex(),
        "pt_hex":    pt.hex(),
        "ct_hex":    ct.hex(),
        "tag_hex":   tag.hex(),
    })

    return vectors


def print_sv_parameters(vectors: dict):
    """Output as SystemVerilog localparams for use in testbenches."""
    print("// Auto-generated by reference_model.py")
    print("// DO NOT EDIT MANUALLY")
    print("")

    cc = vectors["chacha20"]
    for i, v in enumerate(cc):
        print(f"// {v['name']}")
        print(f"localparam [255:0] CC_KEY_{i}   = 256'h{v['key']};")
        print(f"localparam  [95:0] CC_NONCE_{i} = 96'h{v['nonce']};")
        words = v["keystream_words_le"]
        ks_hex = "".join(f"{w:08x}" for w in reversed(words))
        print(f"localparam [511:0] CC_KS_{i}    = 512'h{ks_hex};")
        print("")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--sv",   action="store_true")
    args = parser.parse_args()

    vectors = {
        "chacha20": generate_chacha20_vectors(),
        "des":      generate_des_vectors(),
        "aes256":   generate_aes256_vectors(),
        "aes_gcm":  generate_aes_gcm_vectors(),
    }

    if args.json:
        print(json.dumps(vectors, indent=2))
    elif args.sv:
        print_sv_parameters(vectors)
    else:
        # Human-readable output
        print("=" * 70)
        print("open-crypto-hdl — Reference Test Vectors")
        print("=" * 70)

        print("\n── ChaCha20 ──")
        for v in vectors["chacha20"]:
            print(f"  [{v['name']}]")
            print(f"    key:    {v['key'][:32]}...")
            print(f"    nonce:  {v['nonce']}")
            print(f"    ctr:    {v['counter']}")
            words = v["keystream_words_le"]
            print(f"    ks[0]:  0x{words[0]:08x}")
            print(f"    ks[1]:  0x{words[1]:08x}")
            print(f"    ks[2]:  0x{words[2]:08x}")
            print(f"    ks[3]:  0x{words[3]:08x}")

        print("\n── DES ──")
        for v in vectors["des"]:
            print(f"  key={v['key_hex']} pt={v['pt_hex']} → ct={v['ct_hex']}")

        print("\n── AES-256 ECB ──")
        for v in vectors["aes256"]:
            print(f"  [{v['name']}]")
            print(f"    pt:  {v['pt_hex']}")
            print(f"    ct:  {v['ct_hex']}")

        print("\n── AES-256-GCM ──")
        for v in vectors["aes_gcm"]:
            print(f"  [{v['name']}]")
            print(f"    pt:  {v['pt_hex']}")
            print(f"    ct:  {v['ct_hex']}")
            print(f"    tag: {v['tag_hex']}")


if __name__ == "__main__":
    main()
