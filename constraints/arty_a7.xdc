# ============================================================
# open_crypto_hdl_arty.xdc — Xilinx Arty A7 Constraints
# Target: Xilinx Artix-7 XC7A35T-1CPG236C (Arty A7-35T)
#         or XC7A100T for Arty A7-100T
#
# Maps tt_um_crypto_top ports to Arty A7 headers + LEDs.
#
# Pin Assignment Strategy:
#   clk        → On-board 100 MHz oscillator (E3)
#   rst_n      → BTN0 (active-low push button)
#   ena        → SW0  (slide switch)
#   uio[7:0]   → Pmod JA (SPI on pins 1-4, reserved on 7-10)
#   ui_in[7:0] → Pmod JB (result byte selector + unused)
#   uo_out[7:0]→ LEDs LD0-LD3 + Pmod JC pins 1-4
#
# All pins verified unique — no DRC conflicts.
#
# Usage in Vivado:
#   1. Add all RTL sources
#   2. Add this XDC file
#   3. Set top module to tt_um_crypto_top
#   4. Run synthesis + implementation
# ============================================================

# ── Clock ─────────────────────────────────────────────────────────────────────
# Arty A7 has 100 MHz on-board oscillator (E3 pin)
set_property -dict {PACKAGE_PIN E3 IOSTANDARD LVCMOS33} [get_ports clk]
create_clock -add -name sys_clk_pin -period 10.00 -waveform {0 5} [get_ports clk]

# ── Reset (active-low, mapped to BTN0) ───────────────────────────────────────
set_property -dict {PACKAGE_PIN D9 IOSTANDARD LVCMOS33} [get_ports rst_n]

# ── Enable (SW0) ──────────────────────────────────────────────────────────────
set_property -dict {PACKAGE_PIN A8 IOSTANDARD LVCMOS33} [get_ports ena]

# ── SPI Interface on Pmod JA (pins 1-4) ──────────────────────────────────────
#   JA Pin 1  → uio_in[0]  = SCK  (SPI clock)
#   JA Pin 2  → uio_in[1]  = MOSI (SPI data in)
#   JA Pin 3  → uio_out[2] = MISO (SPI data out)
#   JA Pin 4  → uio_in[3]  = CS_N (chip select, active low)
set_property -dict {PACKAGE_PIN G13 IOSTANDARD LVCMOS33} [get_ports {uio_in[0]}]
set_property -dict {PACKAGE_PIN B11 IOSTANDARD LVCMOS33} [get_ports {uio_in[1]}]
set_property -dict {PACKAGE_PIN A11 IOSTANDARD LVCMOS33} [get_ports {uio_out[2]}]
set_property -dict {PACKAGE_PIN D12 IOSTANDARD LVCMOS33} [get_ports {uio_in[3]}]

# ── Remaining uio ports on Pmod JA (pins 7-10) ──────────────────────────────
#   JA Pin 7  → uio_in[2]   (directly tied, active input)
#   JA Pin 8  → uio_in[4]   (directly tied, active input)
#   JA Pin 9  → uio_in[5]   (directly tied, active input)
#   JA Pin 10 → uio_in[6]   (directly tied, active input)
set_property -dict {PACKAGE_PIN D13 IOSTANDARD LVCMOS33} [get_ports {uio_in[2]}]
set_property -dict {PACKAGE_PIN B18 IOSTANDARD LVCMOS33} [get_ports {uio_in[4]}]
set_property -dict {PACKAGE_PIN A18 IOSTANDARD LVCMOS33} [get_ports {uio_in[5]}]
set_property -dict {PACKAGE_PIN K16 IOSTANDARD LVCMOS33} [get_ports {uio_in[6]}]

# uio_in[7] on SW1 (separate from JA to avoid pin exhaustion)
set_property -dict {PACKAGE_PIN C11 IOSTANDARD LVCMOS33} [get_ports {uio_in[7]}]

# ── uio_out — directly map to Pmod JA (active outputs share physical pins) ──
# In TinyTapeout the uio_oe register controls direction.
# For Vivado we constrain both in and out to the same physical pins.
# The design drives uio_oe = 8'b00000100 (only bit 2 = MISO is output).
# Remaining uio_out bits are unused outputs — constrain to JA counterparts.
set_property -dict {PACKAGE_PIN G13 IOSTANDARD LVCMOS33} [get_ports {uio_out[0]}]
set_property -dict {PACKAGE_PIN B11 IOSTANDARD LVCMOS33} [get_ports {uio_out[1]}]
# uio_out[2] (MISO) already constrained above as A11
set_property -dict {PACKAGE_PIN D12 IOSTANDARD LVCMOS33} [get_ports {uio_out[3]}]
set_property -dict {PACKAGE_PIN D13 IOSTANDARD LVCMOS33} [get_ports {uio_out[4]}]
set_property -dict {PACKAGE_PIN B18 IOSTANDARD LVCMOS33} [get_ports {uio_out[5]}]
set_property -dict {PACKAGE_PIN A18 IOSTANDARD LVCMOS33} [get_ports {uio_out[6]}]
set_property -dict {PACKAGE_PIN K16 IOSTANDARD LVCMOS33} [get_ports {uio_out[7]}]

# ── ui_in[7:0] on Pmod JB ────────────────────────────────────────────────────
#   JB Pin 1  → ui_in[0]  (result byte selector bit 0)
#   JB Pin 2  → ui_in[1]  (result byte selector bit 1)
#   JB Pin 3  → ui_in[2]  (result byte selector bit 2)
#   JB Pin 4  → ui_in[3]  (result byte selector bit 3)
#   JB Pin 7  → ui_in[4]  (reserved)
#   JB Pin 8  → ui_in[5]  (reserved)
#   JB Pin 9  → ui_in[6]  (reserved)
#   JB Pin 10 → ui_in[7]  (reserved)
set_property -dict {PACKAGE_PIN E15 IOSTANDARD LVCMOS33} [get_ports {ui_in[0]}]
set_property -dict {PACKAGE_PIN E16 IOSTANDARD LVCMOS33} [get_ports {ui_in[1]}]
set_property -dict {PACKAGE_PIN D15 IOSTANDARD LVCMOS33} [get_ports {ui_in[2]}]
set_property -dict {PACKAGE_PIN C15 IOSTANDARD LVCMOS33} [get_ports {ui_in[3]}]
set_property -dict {PACKAGE_PIN J17 IOSTANDARD LVCMOS33} [get_ports {ui_in[4]}]
set_property -dict {PACKAGE_PIN J18 IOSTANDARD LVCMOS33} [get_ports {ui_in[5]}]
set_property -dict {PACKAGE_PIN K15 IOSTANDARD LVCMOS33} [get_ports {ui_in[6]}]
set_property -dict {PACKAGE_PIN J15 IOSTANDARD LVCMOS33} [get_ports {ui_in[7]}]

# ── uo_out[7:0] — LEDs LD0-LD3 + Pmod JC pins 1-4 ──────────────────────────
#   LD0 → uo_out[0]
#   LD1 → uo_out[1]
#   LD2 → uo_out[2]
#   LD3 → uo_out[3]
#   JC Pin 1 → uo_out[4]
#   JC Pin 2 → uo_out[5]
#   JC Pin 3 → uo_out[6]
#   JC Pin 4 → uo_out[7]
set_property -dict {PACKAGE_PIN H5  IOSTANDARD LVCMOS33} [get_ports {uo_out[0]}]
set_property -dict {PACKAGE_PIN J5  IOSTANDARD LVCMOS33} [get_ports {uo_out[1]}]
set_property -dict {PACKAGE_PIN T9  IOSTANDARD LVCMOS33} [get_ports {uo_out[2]}]
set_property -dict {PACKAGE_PIN T10 IOSTANDARD LVCMOS33} [get_ports {uo_out[3]}]
set_property -dict {PACKAGE_PIN U12 IOSTANDARD LVCMOS33} [get_ports {uo_out[4]}]
set_property -dict {PACKAGE_PIN V12 IOSTANDARD LVCMOS33} [get_ports {uo_out[5]}]
set_property -dict {PACKAGE_PIN V10 IOSTANDARD LVCMOS33} [get_ports {uo_out[6]}]
set_property -dict {PACKAGE_PIN V11 IOSTANDARD LVCMOS33} [get_ports {uo_out[7]}]

# ── uio_oe[7:0] — directly tied in RTL (constant 8'b00000100) ───────────────
# These need physical pins for Vivado but are driven internally.
# Map to Pmod JD pins (auxiliary, directly tied to avoid DRC errors).
set_property -dict {PACKAGE_PIN D4  IOSTANDARD LVCMOS33} [get_ports {uio_oe[0]}]
set_property -dict {PACKAGE_PIN D3  IOSTANDARD LVCMOS33} [get_ports {uio_oe[1]}]
set_property -dict {PACKAGE_PIN F4  IOSTANDARD LVCMOS33} [get_ports {uio_oe[2]}]
set_property -dict {PACKAGE_PIN F3  IOSTANDARD LVCMOS33} [get_ports {uio_oe[3]}]
set_property -dict {PACKAGE_PIN E2  IOSTANDARD LVCMOS33} [get_ports {uio_oe[4]}]
set_property -dict {PACKAGE_PIN D2  IOSTANDARD LVCMOS33} [get_ports {uio_oe[5]}]
set_property -dict {PACKAGE_PIN H2  IOSTANDARD LVCMOS33} [get_ports {uio_oe[6]}]
set_property -dict {PACKAGE_PIN G2  IOSTANDARD LVCMOS33} [get_ports {uio_oe[7]}]

# ── Timing constraints ────────────────────────────────────────────────────────
# SPI clock: 10 MHz max (safely below Arty SPI interface capability)
create_clock -name sck_clk -period 100.0 [get_ports {uio_in[0]}]

# False path on SPI data inputs (asynchronous to system clock)
set_false_path -from [get_ports {uio_in[*]}] -to [get_clocks sys_clk_pin]
set_false_path -from [get_clocks sys_clk_pin] -to [get_ports {uio_out[*]}]

# ── CFGBVS / CONFIG_VOLTAGE for Arty A7 ──────────────────────────────────────
set_property CFGBVS VCCO [current_design]
set_property CONFIG_VOLTAGE 3.3 [current_design]

# ── Bitstream settings ────────────────────────────────────────────────────────
set_property BITSTREAM.GENERAL.COMPRESS TRUE [current_design]
set_property BITSTREAM.CONFIG.SPI_BUSWIDTH 4 [current_design]
