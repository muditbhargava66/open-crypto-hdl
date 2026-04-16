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
        begin
            // First pass reduction
            v1 = {1'b0, val[129:0]} + ({130'd0, val[130]} * 3'd5);
            // Second pass: if v1 >= 2^130-5, subtract 2^130-5
            // 2^130-5 is 131'h3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFB
            if (v1 >= 131'h3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFB)
                strict_reduce = v1 - 131'h3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFB;
            else
                strict_reduce = v1[129:0];
        end
    endfunction

    wire [127:0] block_le = brevs(block);

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
                            5'd1:  acc <= acc + {122'd1, block_le[7:0]};
                            5'd2:  acc <= acc + {114'd1, block_le[15:0]};
                            5'd3:  acc <= acc + {106'd1, block_le[23:0]};
                            5'd4:  acc <= acc + {98'd1,  block_le[31:0]};
                            5'd5:  acc <= acc + {90'd1,  block_le[39:0]};
                            5'd6:  acc <= acc + {82'd1,  block_le[47:0]};
                            5'd7:  acc <= acc + {74'd1,  block_le[55:0]};
                            5'd8:  acc <= acc + {66'd1,  block_le[63:0]};
                            5'd9:  acc <= acc + {58'd1,  block_le[71:0]};
                            5'd10: acc <= acc + {50'd1,  block_le[79:0]};
                            5'd11: acc <= acc + {42'd1,  block_le[87:0]};
                            5'd12: acc <= acc + {34'd1,  block_le[95:0]};
                            5'd13: acc <= acc + {26'd1,  block_le[103:0]};
                            5'd14: acc <= acc + {18'd1,  block_le[111:0]};
                            5'd15: acc <= acc + {10'd1,  block_le[119:0]};
                            5'd16: acc <= acc + {2'b0,   1'b1, block_le[127:0]};
                            default: acc <= acc + {2'b0, 1'b1, block_le[127:0]};
                        endcase
                        state   <= S_PRE_MULT;
                    end
                end
                S_PRE_MULT: begin
                    mult_a <= {1'b0, strict_reduce(acc)};
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
                        tag       <= brevs(strict_reduce(mult_p) + s);
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
