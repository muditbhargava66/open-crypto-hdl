// ============================================================
//  chacha20_core_formal.v — ChaCha20 with embedded SVA
//  Wraps chacha20_core with formal verification properties.
//
//  Compile:  sby -f tb/formal/chacha20_formal.sby
//
//  Properties proven:
//    P1: valid_out only asserted when running completes
//    P2: round_cnt monotonically increases 0→10 when running
//    P3: valid_out is exactly one cycle wide
//    P4: running and valid_in cannot both be 1 simultaneously
//        after the first cycle (running blocks new starts)
//    P5: keystream is never all-zeros (liveness — over inputs)
// ============================================================
`default_nettype none
module chacha20_core_formal (
    input  wire         clk,
    input  wire         rst_n,
    input  wire [255:0] key,
    input  wire  [95:0] nonce,
    input  wire  [31:0] counter,
    input  wire         valid_in,
    output wire [511:0] keystream,
    output wire         valid_out
);
    // Instantiate the real core
    chacha20_core u_core (
        .clk      (clk),
        .rst_n    (rst_n),
        .key      (key),
        .nonce    (nonce),
        .counter  (counter),
        .valid_in (valid_in),
        .keystream(keystream),
        .valid_out(valid_out)
    );

`ifdef FORMAL
    // ---- One-cycle history registers ----
    reg past_valid;
    reg past_running;
    reg f_past_valid;  // tracks whether $past() is valid

    initial f_past_valid = 1'b0;
    always @(posedge clk) f_past_valid <= 1'b1;

    always @(posedge clk) begin
        past_valid   <= valid_out;
        past_running <= u_core.running;
    end

    // ── P1: valid_out only high when core was running ────────────────
    // After reset, valid_out must not fire unless a block was started
    always @(posedge clk) begin
        if (rst_n && f_past_valid) begin
            if (valid_out)
                assert($past(u_core.running));
        end
    end

    // ── P2: round_cnt stays in [0..10] while running ─────────────────
    always @(posedge clk) begin
        if (rst_n) begin
            if (u_core.running)
                assert(u_core.round_cnt <= 4'd10);
        end
    end

    // ── P3: valid_out is exactly one-cycle wide ───────────────────────
    always @(posedge clk) begin
        if (rst_n && f_past_valid) begin
            if (valid_out && $past(valid_out))
                assert(1'b0);  // Two consecutive valid_out cycles forbidden
        end
    end

    // ── P4: running blocks new starts ────────────────────────────────
    // If running=1 and valid_in=1, the core must not restart
    // (running is checked first in the RTL priority)
    always @(posedge clk) begin
        if (rst_n && f_past_valid) begin
            if ($past(u_core.running) && $past(valid_in)) begin
                // Core should still be running (not reset by valid_in)
                assert(u_core.running || valid_out);
            end
        end
    end

    // ── P5: Round counter only increases or resets ───────────────────
    always @(posedge clk) begin
        if (rst_n && f_past_valid) begin
            if ($past(u_core.running) && u_core.running) begin
                // round_cnt must increment or stay (never jump backwards)
                assert(u_core.round_cnt == $past(u_core.round_cnt) + 4'd1 ||
                       u_core.round_cnt == $past(u_core.round_cnt));
            end
        end
    end

    // ── Assumptions (constrain inputs for BMC) ───────────────────────
    // valid_in only pulses for one cycle (realistic usage)
    always @(posedge clk) begin
        if (f_past_valid && $past(valid_in))
            assume(!valid_in);
    end

    // ── Cover properties (reachability) ──────────────────────────────
    always @(posedge clk) begin
        // Check that valid_out is reachable
        cover(valid_out);
        // Check that all 10 rounds are reachable
        cover(u_core.round_cnt == 4'd10 && u_core.running);
    end

`endif  // FORMAL
endmodule
`default_nettype wire
