// ============================================================
//  gf128_mul.v — GF(2^128) Multiplier for GHASH
//  NIST SP 800-38D §6.3
//
//  Implements: Z = X * Y in GF(2^128) with reduction polynomial
//  p(x) = x^128 + x^7 + x^2 + x + 1
//
//  Bit-serial shift-and-XOR, 128 cycles latency.
//  For higher throughput a parallel version would unroll the loop.
//
//  Interface:
//    x[127:0], y[127:0] — operands
//    start              — begin multiplication
//    result[127:0]      — product
//    valid              — result ready
// ============================================================
`default_nettype none
module gf128_mul (
    input  wire         clk,
    input  wire         rst_n,
    input  wire [127:0] x,
    input  wire [127:0] y,
    input  wire         start,
    output reg  [127:0] result,
    output reg          valid
);
    // Reduction polynomial: x^128 + x^7 + x^2 + x + 1
    // In GCM the convention is bit-reversed (MSB is x^0)
    // We use NIST bit ordering throughout.
    localparam [127:0] POLY = 128'hE1000000_00000000_00000000_00000000;

    reg [127:0] Z;   // accumulator
    reg [127:0] V;   // current power of Y
    reg [127:0] Xi;  // remaining bits of X
    reg  [6:0]  cnt; // 0..127
    reg         running;

    // One step of multiplication:
    //   if LSB(Xi) == 1: Z ^= V
    //   V = V >> 1;  if old LSB(V) == 1: V ^= POLY
    //   Xi = Xi >> 1
    wire        xi_bit = Xi[127];   // MSB = x^0 in GCM convention
    wire        v_lsb  = V[0];      // LSB = x^127

    wire [127:0] Z_next = xi_bit ? (Z ^ V) : Z;
    wire [127:0] V_shr  = {1'b0, V[127:1]};
    wire [127:0] V_next = v_lsb ? (V_shr ^ POLY) : V_shr;
    wire [127:0] Xi_next = {Xi[126:0], 1'b0};

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            running <= 1'b0;
            valid   <= 1'b0;
            Z       <= 128'd0;
            V       <= 128'd0;
            Xi      <= 128'd0;
            cnt     <= 7'd0;
        end else begin
            valid <= 1'b0;

            if (start && !running) begin
                Z       <= 128'd0;
                V       <= y;
                Xi      <= x;
                cnt     <= 7'd0;
                running <= 1'b1;
            end else if (running) begin
                Z  <= Z_next;
                V  <= V_next;
                Xi <= Xi_next;

                if (cnt == 7'd127) begin
                    result  <= Z_next;
                    valid   <= 1'b1;
                    running <= 1'b0;
                end else begin
                    cnt <= cnt + 7'd1;
                end
            end
        end
    end
endmodule
`default_nettype wire
