# ============================================================
# Makefile — open-crypto-hdl
# All simulation, synthesis, formal, and ASIC targets
# ============================================================

# ---- Tool detection ----
IVERILOG   ?= iverilog
VVP        ?= vvp
YOSYS      ?= yosys
VERILATOR  ?= verilator
SBY        ?= sby
PYTHON     ?= python3

# ---- Source lists ----
CHACHA_SRCS  = src/chacha20_qr.v src/chacha20_core.v
POLY_SRCS    = src/poly1305_core.v
C20P_SRCS    = $(CHACHA_SRCS) $(POLY_SRCS) src/chacha20poly1305_top.v
AES_SRCS     = src/aes_core.v
AES_CTR_SRCS = $(AES_SRCS) src/aes_ctr.v
GCM_SRCS     = src/gf128_mul.v src/ghash_core.v
AES_GCM_SRCS = $(AES_SRCS) $(GCM_SRCS) src/aes_gcm_top.v
DES_SRCS     = src/des_core.v
TDES_SRCS    = $(DES_SRCS) src/tdes_core.v
TT_SRCS      = $(AES_GCM_SRCS) $(C20P_SRCS) $(DES_SRCS) src/tt_um_crypto_top.v
FORMAL_SRCS  = $(CHACHA_SRCS) src/chacha20_core_formal.v

# ---- Build directory ----
BUILD := build
$(shell mkdir -p $(BUILD))

# ============================================================
# DEFAULT
# ============================================================
.PHONY: all
all: lint sim-all synth-report
	@echo ""
	@echo "╔═══════════════════════════════════════════╗"
	@echo "║  open-crypto-hdl — all targets complete   ║"
	@echo "╚═══════════════════════════════════════════╝"

# ============================================================
# SIMULATION — Icarus Verilog (direct)
# ============================================================
.PHONY: sim-all sim-chacha20 sim-des sim-tdes

sim-all: sim-chacha20 sim-des sim-tdes
	@echo "All Icarus simulations passed"

sim-chacha20: $(BUILD)/sim_chacha20
	@echo "==> Running ChaCha20 simulation..."
	@$(VVP) $< && echo "ChaCha20: ALL TESTS PASSED"

sim-des: $(BUILD)/sim_des
	@echo "==> Running DES simulation..."
	@$(VVP) $< && echo "DES: ALL TESTS PASSED"

sim-tdes: $(BUILD)/sim_tdes
	@echo "==> Running 3DES simulation..."
	@$(VVP) $< && echo "3DES: ALL TESTS PASSED"

$(BUILD)/sim_chacha20: $(CHACHA_SRCS) tb/sv/tb_chacha20.sv
	$(IVERILOG) -g2012 $^ -o $@

$(BUILD)/sim_des: $(DES_SRCS) tb/sv/tb_des.sv
	$(IVERILOG) -g2012 $^ -o $@

$(BUILD)/sim_tdes: $(TDES_SRCS) tb/sv/tb_tdes.sv
	$(IVERILOG) -g2012 $^ -o $@

# ============================================================
# SIMULATION — cocotb
# ============================================================
.PHONY: cocotb-all cocotb-chacha20 cocotb-des cocotb-aes
.PHONY: cocotb-gf128 cocotb-ghash cocotb-poly1305
.PHONY: cocotb-aes-ctr cocotb-aes-gcm cocotb-chacha20poly1305

cocotb-all: cocotb-chacha20 cocotb-des cocotb-aes cocotb-gf128 cocotb-ghash cocotb-poly1305
	@echo "All cocotb simulations passed"

cocotb-chacha20:
	@echo "==> cocotb ChaCha20..."
	rm -rf sim_build
	TOPLEVEL=chacha20_core MODULE=tb.cocotb.test_chacha20 \
	VERILOG_SOURCES="$(CHACHA_SRCS)" SIM=icarus \
	$(MAKE) -f $$(cocotb-config --makefiles)/Makefile.sim

cocotb-des:
	@echo "==> cocotb DES..."
	rm -rf sim_build
	TOPLEVEL=des_core MODULE=tb.cocotb.test_des \
	VERILOG_SOURCES="$(DES_SRCS)" SIM=icarus \
	$(MAKE) -f $$(cocotb-config --makefiles)/Makefile.sim

cocotb-aes:
	@echo "==> cocotb AES-256..."
	rm -rf sim_build
	TOPLEVEL=aes_core MODULE=tb.cocotb.test_aes \
	VERILOG_SOURCES="$(AES_SRCS)" SIM=icarus \
	$(MAKE) -f $$(cocotb-config --makefiles)/Makefile.sim

cocotb-gf128:
	@echo "==> cocotb GF(2^128) multiplier..."
	rm -rf sim_build
	TOPLEVEL=gf128_mul MODULE=tb.cocotb.test_gf128_mul \
	VERILOG_SOURCES="src/gf128_mul.v" SIM=icarus \
	$(MAKE) -f $$(cocotb-config --makefiles)/Makefile.sim

cocotb-ghash:
	@echo "==> cocotb GHASH..."
	rm -rf sim_build
	TOPLEVEL=ghash_core MODULE=tb.cocotb.test_ghash \
	VERILOG_SOURCES="$(GCM_SRCS)" SIM=icarus \
	$(MAKE) -f $$(cocotb-config --makefiles)/Makefile.sim

cocotb-poly1305:
	@echo "==> cocotb Poly1305..."
	rm -rf sim_build
	TOPLEVEL=poly1305_core MODULE=tb.cocotb.test_poly1305 \
	VERILOG_SOURCES="$(POLY_SRCS)" SIM=icarus \
	$(MAKE) -f $$(cocotb-config --makefiles)/Makefile.sim

cocotb-aes-ctr:
	@echo "==> cocotb AES-CTR..."
	rm -rf sim_build
	TOPLEVEL=aes_ctr MODULE=tb.cocotb.test_aes_ctr \
	VERILOG_SOURCES="$(AES_CTR_SRCS)" SIM=icarus \
	$(MAKE) -f $$(cocotb-config --makefiles)/Makefile.sim

cocotb-aes-gcm:
	@echo "==> cocotb AES-GCM..."
	rm -rf sim_build
	TOPLEVEL=aes_gcm_top MODULE=tb.cocotb.test_aes_gcm \
	VERILOG_SOURCES="$(AES_GCM_SRCS)" SIM=icarus \
	$(MAKE) -f $$(cocotb-config --makefiles)/Makefile.sim

cocotb-chacha20poly1305:
	@echo "==> cocotb ChaCha20-Poly1305..."
	rm -rf sim_build
	TOPLEVEL=chacha20poly1305_top MODULE=tb.cocotb.test_chacha20poly1305 \
	VERILOG_SOURCES="$(C20P_SRCS)" SIM=icarus \
	$(MAKE) -f $$(cocotb-config --makefiles)/Makefile.sim

# ============================================================
# LINT — Verilator
# ============================================================
.PHONY: lint lint-chacha20 lint-des lint-aes lint-gcm lint-tt

lint: lint-chacha20 lint-des lint-aes lint-gcm lint-tt
	@echo "All lint checks passed"

lint-chacha20:
	$(VERILATOR) --lint-only -Wall $(CHACHA_SRCS)

lint-des:
	$(VERILATOR) --lint-only -Wall $(DES_SRCS)
	$(VERILATOR) --lint-only -Wall $(TDES_SRCS)

lint-aes:
	$(VERILATOR) --lint-only -Wall $(AES_SRCS)
	$(VERILATOR) --lint-only -Wall $(AES_CTR_SRCS)

lint-gcm:
	$(VERILATOR) --lint-only -Wall $(GCM_SRCS)
	$(VERILATOR) --lint-only -Wall $(AES_GCM_SRCS)

lint-tt:
	$(VERILATOR) --lint-only -Wall $(TT_SRCS)

# ============================================================
# SYNTHESIS — Yosys
# ============================================================
.PHONY: synth-all synth-chacha20 synth-des synth-tdes synth-aes synth-gcm synth-tt synth-report

synth-all: synth-chacha20 synth-des synth-tdes synth-aes synth-gcm synth-tt

synth-chacha20: $(BUILD)/chacha20_netlist.v
$(BUILD)/chacha20_netlist.v: $(CHACHA_SRCS)
	$(YOSYS) -p "read_verilog $^; synth -top chacha20_core -flatten; \
	  stat; write_verilog $@"

synth-des: $(BUILD)/des_netlist.v
$(BUILD)/des_netlist.v: $(DES_SRCS)
	$(YOSYS) -p "read_verilog $^; synth -top des_core -flatten; \
	  stat; write_verilog $@"

synth-tdes: $(BUILD)/tdes_netlist.v
$(BUILD)/tdes_netlist.v: $(TDES_SRCS)
	$(YOSYS) -p "read_verilog $^; synth -top tdes_core -flatten; \
	  stat; write_verilog $@"

synth-aes: $(BUILD)/aes_netlist.v
$(BUILD)/aes_netlist.v: $(AES_SRCS)
	$(YOSYS) -p "read_verilog $^; synth -top aes_core; \
	  stat; write_verilog $@"

synth-gcm: $(BUILD)/ghash_netlist.v
$(BUILD)/ghash_netlist.v: $(GCM_SRCS)
	$(YOSYS) -p "read_verilog $^; synth -top ghash_core -flatten; \
	  stat; write_verilog $@"

synth-tt:
	$(YOSYS) -p "read_verilog $(TT_SRCS); synth -top tt_um_crypto_top; stat;"

synth-report:
	@echo ""
	@echo "╔══════════════════════════════════════════════════╗"
	@echo "║          Synthesis Cell Count Summary            ║"
	@echo "╠══════════════════════════════════════════════════╣"
	@for entry in \
	  "chacha20_qr|src/chacha20_qr.v" \
	  "chacha20_core|src/chacha20_qr.v src/chacha20_core.v" \
	  "des_core|src/des_core.v" \
	  "gf128_mul|src/gf128_mul.v" \
	  "ghash_core|src/gf128_mul.v src/ghash_core.v"; do \
	    top="$${entry%%|*}"; files="$${entry#*|}"; \
	    cells=$$($(YOSYS) -q -p "read_verilog $$files; synth -top $$top; stat;" 2>&1 \
	      | grep "Number of cells" | tail -1 | awk '{print $$NF}'); \
	    printf "  %-20s %10s cells\n" "$$top" "$$cells"; \
	done

# ============================================================
# AREA ESTIMATE — full script
# ============================================================
.PHONY: area
area:
	$(YOSYS) syn/yosys/area_estimate.ys

# ============================================================
# REFERENCE VECTORS
# ============================================================
.PHONY: vectors vectors-json vectors-sv

vectors:
	$(PYTHON) tb/reference_model.py

vectors-json:
	$(PYTHON) tb/reference_model.py --json > $(BUILD)/test_vectors.json
	@echo "Written: $(BUILD)/test_vectors.json"

vectors-sv:
	$(PYTHON) tb/reference_model.py --sv > $(BUILD)/test_vectors_pkg.sv
	@echo "Written: $(BUILD)/test_vectors_pkg.sv"

# ============================================================
# SPI DRIVER
# ============================================================
.PHONY: spi-test
spi-test:
	$(PYTHON) tb/spi_driver.py --test

# ============================================================
# FORMAL VERIFICATION
# ============================================================
.PHONY: formal formal-chacha

formal: formal-chacha

formal-chacha:
	$(SBY) -f tb/formal/chacha20_formal.sby

# ============================================================
# TINYTAPEOUT & ASIC FLOW
# ============================================================
.PHONY: tt-harden tt-png tt-klayout tt-lint

tt-harden:
	./tt/tt_tool.py --create-user-config
	./tt/tt_tool.py --harden

tt-png:
	mkdir -p runs/wokwi/final/gds/
	ln -sf $$(pwd)/runs/wokwi/*-klayout-streamout/*.klayout.gds runs/wokwi/final/gds/tt_um_crypto_top.gds
	./tt/tt_tool.py --create-png
	./tt/tt_tool.py --create-svg
	mv gds_render.png layout.png
	mv gds_render_preview.svg layout.svg
	rm -f gds_render_preview.png gds_render.svg

tt-klayout:
	./tt/tt_tool.py --open-in-klayout

tt-lint:
	@echo "==> TinyTapeout compliance check..."
	$(YOSYS) -p "read_verilog $(TT_SRCS); \
	  hierarchy -check -top tt_um_crypto_top; proc; opt_clean; stat;"
	@echo "tt_um_crypto_top elaborates and has correct hierarchy"

# ============================================================
# FUSESOC
# ============================================================
.PHONY: fusesoc-list fusesoc-sim-chacha fusesoc-sim-des

fusesoc-list:
	fusesoc list-cores

fusesoc-sim-chacha:
	fusesoc run --target sim open-crypto-hdl:chacha20:0.1.0

fusesoc-sim-des:
	fusesoc run --target sim open-crypto-hdl:des:0.1.0

# ============================================================
# DOCUMENTATION
# ============================================================
.PHONY: docs

docs:
	@echo "Synthesis report: docs/synthesis_report.md"
	@cat docs/synthesis_report.md | head -40

# ============================================================
# CLEAN
# ============================================================
.PHONY: clean distclean

clean:
	rm -rf $(BUILD)/ sim_build/ __pycache__ *.vcd *.fst results.xml
	find . -name "*.pyc" -delete
	find . -name "*.log" -delete
	mkdir -p runs/wokwi/final/gds/
	ln -sf $$(pwd)/runs/wokwi/57-klayout-streamout/*.klayout.gds runs/wokwi/final/gds/tt_um_crypto_top.gds
	./tt/tt_tool.py --create-png
	./tt/tt_tool.py --create-svg
	mv gds_render.png layout.png
	mv gds_render_preview.svg layout.svg
	rm -f gds_render_preview.png gds_render.svg

# ============================================================
# WAVEFORM VIEWING
# ============================================================
.PHONY: waves-chacha waves-des waves-aes

waves-chacha: 
	gtkwave tb_chacha20.vcd

waves-des:
	gtkwave tb_des.vcd

waves-aes:
	gtkwave tb_aes.vcd

# ============================================================
# HELP
# ============================================================
.PHONY: help

help:
	@echo ""
	@echo "open-crypto-hdl -- Available targets:"
	@echo ""
	@echo "  SIMULATION (Icarus Verilog):"
	@echo "    sim-all              Run all Icarus Verilog testbenches"
	@echo "    sim-chacha20         ChaCha20 RFC 8439 vectors (SV)"
	@echo "    sim-des              DES NIST KAT vectors (SV)"
	@echo "    sim-tdes             3DES NIST SP 800-67 vectors (SV)"
	@echo ""
	@echo "  SIMULATION (cocotb):"
	@echo "    cocotb-all           Run all cocotb testbenches"
	@echo "    cocotb-chacha20      ChaCha20 (3 tests)"
	@echo "    cocotb-des           DES (2 tests)"
	@echo "    cocotb-aes           AES-256 (5 tests)"
	@echo "    cocotb-gf128         GF(2^128) multiplier (4 tests)"
	@echo "    cocotb-ghash         GHASH core (4 tests)"
	@echo "    cocotb-poly1305      Poly1305 MAC (3 tests)"
	@echo "    cocotb-aes-ctr       AES-256-CTR mode (3 tests)"
	@echo "    cocotb-aes-gcm       AES-256-GCM AEAD (3 tests)"
	@echo "    cocotb-chacha20poly1305  ChaCha20-Poly1305 AEAD (3 tests)"
	@echo ""
	@echo "  LINT:"
	@echo "    lint                 Run Verilator lint on all RTL"
	@echo ""
	@echo "  SYNTHESIS:"
	@echo "    synth-all            Synthesize all cores with Yosys"
	@echo "    synth-report         Print cell count summary"
	@echo "    area                 Run full area estimation script"
	@echo ""
	@echo "  FORMAL:"
	@echo "    formal-chacha        SymbiYosys BMC on ChaCha20"
	@echo ""
	@echo "  TINYTAPEOUT:"
	@echo "    tt-lint              Check TT wrapper hierarchy"
	@echo "    tt-harden            Run OpenLane2 ASIC flow"
	@echo ""
	@echo "  UTILITIES:"
	@echo "    vectors              Print all reference test vectors"
	@echo "    vectors-json         Export vectors as JSON"
	@echo "    spi-test             Run SPI driver self-test"
	@echo "    docs                 Show synthesis report"
	@echo "    clean                Remove build artifacts"
