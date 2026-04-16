// ============================================================
//  ghash_core.v — GHASH Function for AES-256-GCM
//  NIST SP 800-38D §6.4
//
//  Computes GHASH_H(A || C || len) where:
//    H   = AES_K(0^128)  — hash subkey (pre-computed externally)
//    A   = additional authenticated data
//    C   = ciphertext
//    len = 64-bit len(A) || 64-bit len(C)
//
//  Interface (streaming):
//    h[127:0]      — hash subkey (provide with init pulse)
//    block[127:0]  — 128-bit input block
//    init          — pulse: reset accumulator and load H
//    next          — pulse: process one block
//    result[127:0] — GHASH output (valid one cycle after final next)
//    ready         — one-cycle pulse when result is valid
// ============================================================
`default_nettype none
module ghash_core (
    input  wire         clk,
    input  wire         rst_n,
    input  wire [127:0] h,
    input  wire [127:0] block,
    input  wire         init,
    input  wire         next,
    output reg  [127:0] result,
    output reg          ready
);
    reg [127:0] acc;   // running accumulator
    reg [127:0] H_reg; // registered hash subkey

    // GF(2^128) multiplier instance
    wire [127:0] gf_x   = acc ^ block;
    wire [127:0] gf_y   = H_reg;
    wire         gf_start;
    wire [127:0] gf_result;
    wire         gf_valid;

    reg          waiting; // waiting for gf_mul to complete
    reg          gf_kick;

    assign gf_start = gf_kick;

    gf128_mul u_gf (
        .clk    (clk),
        .rst_n  (rst_n),
        .x      (gf_x),
        .y      (gf_y),
        .start  (gf_start),
        .result (gf_result),
        .valid  (gf_valid)
    );

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            acc     <= 128'd0;
            H_reg   <= 128'd0;
            ready   <= 1'b0;
            waiting <= 1'b0;
            gf_kick <= 1'b0;
        end else begin
            ready   <= 1'b0;
            gf_kick <= 1'b0;

            if (init) begin
                acc   <= 128'd0;
                H_reg <= h;
            end else if (next && !waiting) begin
                // Kick off GF multiply: (acc ^ block) * H
                gf_kick <= 1'b1;
                waiting <= 1'b1;
            end

            if (gf_valid && waiting) begin
                acc     <= gf_result;
                result  <= gf_result;
                ready   <= 1'b1;
                waiting <= 1'b0;
            end
        end
    end
endmodule
`default_nettype wire
