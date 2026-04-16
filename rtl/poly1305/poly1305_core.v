// ============================================================
//  poly1305_core.v — Poly1305 MAC (Area-Optimized)
//  RFC 8439 §2.5
//
//  Bit-serial implementation for TinyTapeout.
//  Processes one 128-bit block in ~132 cycles.
// ============================================================
`default_nettype none
module poly1305_core (
    input  wire         clk,
    input  wire         rst_n,

    // Key bus [255:0] — packed {bytes[0], bytes[1], ..., bytes[31]}
    input  wire [255:0] key,
    input  wire         init,

    // Block interface
    input  wire [127:0] block,
    input  wire  [4:0]  block_len,
    input  wire         last_block,
    input  wire         next,

    // Output
    output reg  [127:0] tag,
    output reg          tag_valid,
    output wire         ready
);
    reg [127:0] r;
    reg [127:0] s;

    reg [130:0] acc;
    reg [130:0] mult_a;
    reg [127:0] mult_b;
    reg [130:0] mult_p;

    reg [7:0] bit_cnt;
    reg [1:0] state;
    localparam S_IDLE     = 2'd0;
    localparam S_PRE_MULT = 2'd1;
    localparam S_MULT     = 2'd2;
    localparam S_DONE     = 2'd3;

    assign ready = (state == S_IDLE);

    // Reduction helper: adds (q * 5) to the 130-bit value
    function [130:0] reduce130;
        input [131:0] val;
        begin
            reduce130 = {1'b0, val[129:0]} + ({129'd0, val[131:130]} * 3'd5);
        end
    endfunction

    // Byte reverse helper
    function [127:0] brevs;
        input [127:0] in;
        integer i;
        begin
            brevs = 128'd0;
            for (i=0; i<16; i=i+1)
                brevs[i*8 +: 8] = in[(15-i)*8 +: 8];
        end
    endfunction

    // Strict reduction to [0, 2^130-6]
    function [129:0] strict_reduce;
        input [130:0] val;
        reg [130:0] v1;
        /* verilator lint_off UNUSED */
        reg [130:0] v2;
        /* verilator lint_on UNUSED */
        begin
            // First pass reduction
            v1 = {1'b0, val[129:0]} + ({130'd0, val[130]} * 3'd5);
            // Second pass might still be needed if v1 >= 2^130-5
            if (v1 >= 131'h400000000000000000000000000000005)
                v2 = v1 - 131'h400000000000000000000000000000005;
            else
                v2 = v1;
            strict_reduce = v2[129:0];
        end
    endfunction

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state     <= S_IDLE;
            acc       <= 131'd0;
            tag_valid <= 1'b0;
            bit_cnt   <= 8'd0;
            mult_a    <= 131'd0;
            mult_b    <= 128'd0;
            mult_p    <= 131'd0;
            r         <= 128'd0;
            s         <= 128'd0;
            tag       <= 128'd0;
        end else begin
            tag_valid <= 1'b0;
            case (state)
                S_IDLE: begin
                    if (init) begin
                        r   <= brevs(key[127:0]) & 128'h0ffffffc0ffffffc0ffffffc0fffffff;
                        s   <= brevs(key[255:128]);
                        acc <= 131'd0;
                    end else if (next) begin
                        case (block_len)
                            5'd1:  acc <= acc + {122'd0, 1'b1, block[127:120]};
                            5'd2:  acc <= acc + {114'd0, 1'b1, block[127:120], block[119:112]};
                            5'd3:  acc <= acc + {106'd0, 1'b1, block[127:120], block[119:112], block[111:104]};
                            5'd4:  acc <= acc + {98'd0,  1'b1, block[127:120], block[119:112], block[111:104], block[103:96]};
                            5'd5:  acc <= acc + {90'd0,  1'b1, block[127:120], block[119:112], block[111:104], block[103:96], block[95:88]};
                            5'd6:  acc <= acc + {82'd0,  1'b1, block[127:120], block[119:112], block[111:104], block[103:96], block[95:88], block[87:80]};
                            5'd7:  acc <= acc + {74'd0,  1'b1, block[127:120], block[119:112], block[111:104], block[103:96], block[95:88], block[87:80], block[79:72]};
                            5'd8:  acc <= acc + {66'd0,  1'b1, block[127:120], block[119:112], block[111:104], block[103:96], block[95:88], block[87:80], block[79:72], block[71:64]};
                            5'd9:  acc <= acc + {58'd0,  1'b1, block[127:120], block[119:112], block[111:104], block[103:96], block[95:88], block[87:80], block[79:72], block[71:64], block[63:56]};
                            5'd10: acc <= acc + {50'd0,  1'b1, block[127:120], block[119:112], block[111:104], block[103:96], block[95:88], block[87:80], block[79:72], block[71:64], block[63:56], block[55:48]};
                            5'd11: acc <= acc + {42'd0,  1'b1, block[127:120], block[119:112], block[111:104], block[103:96], block[95:88], block[87:80], block[79:72], block[71:64], block[63:56], block[55:48], block[47:40]};
                            5'd12: acc <= acc + {34'd0,  1'b1, block[127:120], block[119:112], block[111:104], block[103:96], block[95:88], block[87:80], block[79:72], block[71:64], block[63:56], block[55:48], block[47:40], block[39:32]};
                            5'd13: acc <= acc + {26'd0,  1'b1, block[127:120], block[119:112], block[111:104], block[103:96], block[95:88], block[87:80], block[79:72], block[71:64], block[63:56], block[55:48], block[47:40], block[39:32], block[31:24]};
                            5'd14: acc <= acc + {18'd0,  1'b1, block[127:120], block[119:112], block[111:104], block[103:96], block[95:88], block[87:80], block[79:72], block[71:64], block[63:56], block[55:48], block[47:40], block[39:32], block[31:24], block[23:16]};
                            5'd15: acc <= acc + {10'd0,  1'b1, block[127:120], block[119:112], block[111:104], block[103:96], block[95:88], block[87:80], block[79:72], block[71:64], block[63:56], block[55:48], block[47:40], block[39:32], block[31:24], block[23:16], block[15:8]};
                            5'd16: acc <= acc + {2'b0,   1'b1, brevs(block)};
                            default: acc <= acc + {2'b0, 1'b1, brevs(block)};
                        endcase
                        state   <= S_PRE_MULT;
                    end
                end
                S_PRE_MULT: begin
                    mult_a <= reduce130({1'b0, acc});
                    mult_b <= r;
                    mult_p <= 131'd0;
                    bit_cnt <= 8'd0;
                    state   <= S_MULT;
                end
                S_MULT: begin
                    if (mult_b[0])
                        mult_p <= reduce130({1'b0, mult_p} + {1'b0, mult_a});
                    
                    mult_a  <= reduce130({mult_a, 1'b0});
                    mult_b  <= {1'b0, mult_b[127:1]};
                    bit_cnt <= bit_cnt + 8'd1;
                    if (bit_cnt == 8'd127) state <= S_DONE;
                end
                S_DONE: begin
                    acc <= mult_p;
                    if (last_block) begin
                        /* verilator lint_off WIDTH */
                        tag       <= strict_reduce(mult_p) + s;
                        /* verilator lint_on WIDTH */
                        tag_valid <= 1'b1;
                    end
                    state <= S_IDLE;
                end
                default: state <= S_IDLE;
            endcase
        end
    end
endmodule
