# open-crypto-hdl — ASIC Implementation & GDS Report

## Implementation Overview
The open-crypto-hdl cryptographic suite is designed for silicon implementation using the sky130A (SkyWater 130nm) process. The implementation leverages an area-optimized iterative architecture to fit within the constraints of the TinyTapeout platform.

## Physical Design Flow
The GDSII layout is generated using the OpenLane 2 automated RTL-to-GDS flow.

1. **Synthesis**: Yosys processes the Verilog RTL, mapping logic to the sky130_fd_sc_hd standard cell library.
2. **Floorplanning**: The design is placed within a 460µm x 172µm die area (corresponding to a 2x2 TinyTapeout tile configuration).
3. **Placement**: Standard cells are placed with a target density of 50%, ensuring sufficient routing resources.
4. **Clock Tree Synthesis (CTS)**: A balanced clock tree is constructed for the 50MHz target frequency (tested up to 100MHz).
5. **Routing**: Global and detailed routing performed via OpenROAD, restricted to metal layers 1 through 4.
6. **Sign-off**: DRC/LVS checks performed using Magic and Netgen.

## Area and Density Reports
The design is highly consolidated through iterative datapath sharing.

| Metric              | Value            |
|---------------------|------------------|
| Total Cell Count    | 4,666            |
| Standard Cell Area  | ~18,200 µm²      |
| Core Utilization    | 24.5%            |
| Power Pads          | vccd1 / vssd1    |

## Register File & Interface
Communication with the crypto cores is handled via a robust SPI peripheral (MISO/MOSI).

| Address Range | Description       | Access |
|---------------|-------------------|--------|
| 0x00          | Cipher Selection  | R/W    |
| 0x01          | Command Register  | W      |
| 0x02          | Status Register   | R      |
| 0x10 - 0x2F   | Key Storage (32B) | R/W    |
| 0x30 - 0x3B   | IV Storage (12B)  | R/W    |
| 0x40 - 0x4F   | Data Block (16B)  | R/W    |
| 0x50 - 0x5F   | Result Block (16B)| R      |
| 0x60 - 0x6F   | AEAD Tag (16B)    | R      |

## Performance Sign-off
- **Timing**: No setup/hold violations at 20ns clock period (50MHz).
- **Power**: Estimated peak dynamic power < 10mW at 1.8V.
- **Verification**: Post-synthesis gate-level simulation passed 100% of KAT vectors.

## Layout Visualization
The iterative nature of the cores results in a regular, logic-heavy layout. Most area is occupied by the AES and ChaCha20 state registers. The bit-serial Poly1305 multiplier contributes less than 5% of the total area, a significant reduction from the original parallel implementation.
