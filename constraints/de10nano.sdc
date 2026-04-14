# ============================================================
# de10nano.sdc — Synopsis Design Constraints (Quartus / OpenROAD)
# Target: 50 MHz system clock, SPI max 10 MHz
# ============================================================

# ── Primary clock ─────────────────────────────────────────────────────────────
create_clock -name {clk} -period 20.000 -waveform {0.000 10.000} [get_ports {clk}]

# ── SPI input clock ───────────────────────────────────────────────────────────
# SPI SCK is asynchronous to system clock
create_clock -name {sck} -period 100.000 [get_ports {uio_in[0]}]

# ── Derived clocks ────────────────────────────────────────────────────────────
derive_pll_clocks
derive_clock_uncertainty

# ── False paths ───────────────────────────────────────────────────────────────
# SPI is async to sys clk — use false path for CDC analysis
set_false_path -from [get_clocks {sck}] -to [get_clocks {clk}]
set_false_path -from [get_clocks {clk}] -to [get_clocks {sck}]

# Input constraints (relative to clk)
set_input_delay  -clock clk -max 3.0 [get_ports {ui_in[*]}]
set_input_delay  -clock clk -min 0.5 [get_ports {ui_in[*]}]
set_output_delay -clock clk -max 3.0 [get_ports {uo_out[*]}]
set_output_delay -clock clk -min 0.5 [get_ports {uo_out[*]}]

# ── Multicycle paths ──────────────────────────────────────────────────────────
# AES key expansion involves long combinational chains in tasks.
# Allow 2-cycle paths for synthesis estimation.
set_multicycle_path -from [get_registers {u_aes|*}] -setup 2
set_multicycle_path -from [get_registers {u_aes|*}] -hold  1
