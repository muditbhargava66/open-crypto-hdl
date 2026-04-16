# open-crypto-hdl Pinout and Register Map

## TinyTapeout Interface

| Pin | Type | Name | Description |
|-----|------|------|-------------|
| `clk` | Input | Clock | System clock (target 50-100 MHz) |
| `rst_n` | Input | Reset | Active-low asynchronous reset |
| `uio[0]`| Input | SCK | SPI Serial Clock |
| `uio[1]`| Input | MOSI| SPI Master-Out Slave-In |
| `uio[2]`| Output| MISO| SPI Master-In Slave-Out |
| `uio[3]`| Input | CS_N| SPI Chip Select (Active Low) |
| `ui_in[3:0]` | Input | Byte Select | Index for the result byte shown on `uo_out` |
| `uo_out[7:0]`| Output| Result Byte | Currently selected byte from the result register file |

## SPI Register Map

All register access is 8-bit. Write operations require address and data. Read operations use the same address followed by MISO shifting.

| Address | Name | Access | Bit-field Description |
|---------|------|--------|----------------------|
| `0x00`  | `CIPHER_SEL` | R/W | `00`: DES, `01`: AES-256, `10`: ChaCha20, `11`: Poly1305 |
| `0x01`  | `CMD`        | W   | `0x01`: START, `0x02`: RESET, `0x04`: POLY_INIT |
| `0x02`  | `STATUS`     | R   | `bit 0`: BUSY, `bit 1`: DONE |
| `0x10-0x2F` | `KEY`     | R/W | 256-bit Key storage (used by all cores) |
| `0x30-0x3B` | `IV`      | R/W | 96-bit IV or Nonce storage |
| `0x40-0x4F` | `BLOCK`   | R/W | 128-bit Input block data |
| `0x50-0x5F` | `RESULT`  | R   | 128-bit Output result (Ciphertext/Plaintext) |
| `0x60-0x6F` | `TAG`     | R   | 128-bit Authentication Tag (AES-GCM / Poly1305) |

## Direct Monitoring

The `uo_out` pins reflect the byte selected by `ui_in[3:0]` from the `RESULT` register file (0x50-0x5F). This allows for debugging or low-speed data extraction without using the SPI MISO path.
