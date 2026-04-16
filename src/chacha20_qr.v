// ============================================================
//  chacha20_qr.v — ChaCha20 Quarter Round
//  RFC 8439 §2.1
//
//  Combinational: zero latency, instantiated 4× per round
//  a,b,c,d are 32-bit words; outputs are the updated words.
// ============================================================
`default_nettype none
module chacha20_qr (
    input  wire [31:0] a_in, b_in, c_in, d_in,
    output wire [31:0] a_out, b_out, c_out, d_out
);
    // Step 1: a += b;  d ^= a;  d <<<= 16
    wire [31:0] a1     = a_in + b_in;
    wire [31:0] d1_xor = d_in ^ a1;
    wire [31:0] d1     = {d1_xor[15:0], d1_xor[31:16]};

    // Step 2: c += d;  b ^= c;  b <<<= 12
    wire [31:0] c1     = c_in + d1;
    wire [31:0] b1_xor = b_in ^ c1;
    wire [31:0] b1     = {b1_xor[19:0], b1_xor[31:20]};

    // Step 3: a += b;  d ^= a;  d <<<= 8
    wire [31:0] a2     = a1 + b1;
    wire [31:0] d2_xor = d1 ^ a2;
    wire [31:0] d2     = {d2_xor[23:0], d2_xor[31:24]};

    // Step 4: c += d;  b ^= c;  b <<<= 7
    wire [31:0] c2     = c1 + d2;
    wire [31:0] b2_xor = b1 ^ c2;
    wire [31:0] b2     = {b2_xor[24:0], b2_xor[31:25]};

    assign a_out = a2;
    assign b_out = b2;
    assign c_out = c2;
    assign d_out = d2;
endmodule
`default_nettype wire
