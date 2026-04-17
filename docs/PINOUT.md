# open-crypto-hdl Pinout and Register Map (v1.1.0)

## TinyTapeout Interface

| Pin | Type | Name | Description |
|-----|------|------|-------------|
| `clk` | Input | Clock | System clock (target 20-40 MHz) |
| `rst_n` | Input | Reset | Active-low asynchronous reset |
| `uio[0]`| Input | SCK | SPI Serial Clock (CDC synchronized) |
| `uio[1]`| Input | MOSI| SPI Master-Out Slave-In (CDC synchronized) |
| `uio[2]`| Output| MISO| SPI Master-In Slave-Out |
| `uio[3]`| Input | CS_N| SPI Chip Select (Active Low, CDC synchronized) |
| `ui_in[3:0]` | Input | Byte Select | Index for the result byte shown on `uo_out` |
| `uo_out[7:0]`| Output| Result Byte | Currently selected byte from the result register file |

## SPI Register Map

All register access is 8-bit. AEAD operations require streaming blocks via 0x40.

| Address | Name | Access | Bit-field Description |
|---------|------|--------|----------------------|
| `0x00`  | `CIPHER_SEL` | R/W | `[2:0]`: DES(0), AES(1), ChaCha(2), Poly(3), GCM(4), C20P(5). `[3]`: 1=Enc, 0=Dec. |
| `0x01`  | `CMD`        | W   | `0x01`: START, `0x02`: RESET, `0x04`: POLY_INIT, `0x08`: AEAD_NEXT |
| `0x02`  | `STATUS`     | R   | `bit 0`: BUSY, `bit 1`: DONE, `bit 2`: ERROR/AUTH_FAIL |
| `0x04-0x07` | `AAD_LEN` | R/W | 32-bit AAD length in bytes (Big-Endian) |
| `0x08-0x0B` | `PT_LEN`  | R/W | 32-bit Plaintext/Ciphertext length in bytes (Big-Endian) |
| `0x10-0x2F` | `KEY`     | R/W | 256-bit Key storage (used by all cores) |
| `0x30-0x3B` | `IV`      | R/W | 96-bit IV or Nonce storage |
| `0x40-0x4F` | `BLOCK`   | R/W | 128-bit Input block data (AAD/PT/CT) |
| `0x50-0x5F` | `RESULT`  | R   | 128-bit Output result (Ciphertext/Plaintext) |
| `0x60-0x6F` | `TAG`     | R   | 128-bit Authentication Tag (AES-GCM / Poly1305) |

## Direct Monitoring

The `uo_out` pins reflect the byte selected by `ui_in[3:0]` from the `RESULT` register file (0x50-0x5F). This allows for low-speed debugging without the SPI MISO path.
