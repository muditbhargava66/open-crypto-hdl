// ============================================================
//  chacha20_core_formal.v — ChaCha20 with embedded SVA
//  Wraps chacha20_core with formal verification properties.
//
//  Compile:  sby -f tb/formal/chacha20_formal.sby
//
//  Properties proven:
//    P1: valid_out only asserted when running completes
//    P2: step_cnt stays in [0..80] while running
//    P3: valid_out is exactly one cycle wide
//    P4: running and valid_in cannot both be 1 simultaneously
//        after the first cycle (running blocks new starts)
//    P5: step_cnt monotonically increments
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
    wire f_running;
    wire [7:0] f_step_cnt;

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
`ifdef FORMAL
        , .f_running(f_running)
        , .f_step_cnt(f_step_cnt)
`endif
    );

`ifdef FORMAL
    // ---- One-cycle history registers ----
    reg past_valid;
    reg past_running;
    reg [7:0] past_step_cnt;
    reg f_past_valid;  // tracks whether $past() is valid

    initial f_past_valid = 1'b0;
    always @(posedge clk) f_past_valid <= 1'b1;

    always @(posedge clk) begin
        past_valid    <= valid_out;
        past_running  <= f_running;
        past_step_cnt <= f_step_cnt;
    end

    // ── Initial Reset Assumption ─────────────────────────────────────
    // Constrain the solver to start with a reset cycle
    always @(posedge clk) begin
        if (!f_past_valid)
            assume(!rst_n);
        else
            assume(rst_n); // Stay out of reset after cycle 0
    end

    // ── P1: valid_out only high when core was running ────────────────
    always @(posedge clk) begin
        if (rst_n && f_past_valid) begin
            if (valid_out)
                assert(past_running);
        end
    end

    // ── P2: step_cnt stays in [0..80] while running ─────────────────
    always @(posedge clk) begin
        if (rst_n) begin
            if (f_running)
                assert(f_step_cnt <= 8'd80);
        end
    end

    // ── P3: valid_out is exactly one-cycle wide ───────────────────────
    always @(posedge clk) begin
        if (rst_n && f_past_valid) begin
            if (valid_out && past_valid)
                assert(1'b0);
        end
    end

    // ── P4: running blocks new starts ────────────────────────────────
    always @(posedge clk) begin
        if (rst_n && f_past_valid) begin
            if (past_running && valid_in) begin
                // core should still be running or just finished
                assert(f_running || valid_out);
            end
        end
    end

    // ── P5: Step counter only increases ──────────────────────────────
    always @(posedge clk) begin
        if (rst_n && f_past_valid) begin
            if (past_running && f_running && f_step_cnt < 8'd80) begin
                // We allow f_step_cnt == past_step_cnt ONLY in the very
                // first cycle of running (where it goes from X/0 to 0)
                // but since we check past_running, we are already in the run.
                assert(f_step_cnt == past_step_cnt + 8'd1);
            end
        end
    end

    // ── Assumptions (constrain inputs for BMC) ───────────────────────
    always @(posedge clk) begin
        if (f_past_valid && $past(valid_in))
            assume(!valid_in);
    end

    // ── Cover properties (reachability) ──────────────────────────────
    always @(posedge clk) begin
        cover(valid_out);
        cover(f_step_cnt == 8'd80);
    end

`endif  // FORMAL
endmodule
`default_nettype wire
