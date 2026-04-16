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
    localparam S_IDLE = 2'd0;
    localparam S_MULT = 2'd1;
    localparam S_DONE = 2'd2;

    assign ready = (state == S_IDLE);

    // Reduction helper: adds (q * 5) to the 130-bit value
    function [130:0] reduce130;
        input [131:0] val;
        begin
            reduce130 = {1'b0, val[129:0]} + (val[131:130] * 3'd5);
        end
    endfunction

    // Byte reverse helper
    function [127:0] brevs;
        input [127:0] in;
        integer i;
        begin
            for (i=0; i<16; i=i+1)
                brevs[i*8 +: 8] = in[(15-i)*8 +: 8];
        end
    endfunction

    // Strict reduction to [0, 2^130-6]
    function [129:0] strict_reduce;
        input [130:0] val;
        reg [130:0] v1, v2;
        begin
            // First pass reduction
            v1 = {1'b0, val[129:0]} + (val[130] * 3'd5);
            // Second pass might still be needed if v1 >= 2^130-5
            if (v1 >= 131'h400000000000000000000000000000005)
                v2 = v1 - 131'h400000000000000000000000000000005;
            else
                v2 = v1;
            strict_reduce = v2[129:0];
        end
    endfunction

    wire [127:0] m_masked;
    // Mask block and add hibit
    assign m_masked = 
        (block_len == 5'd1)  ? {120'd0, 8'hFF & block[127:120]} :
        (block_len == 5'd2)  ? {112'd0, 16'hFFFF & block[127:112]} :
        (block_len == 5'd3)  ? {104'd0, 24'hFFFFFF & block[127:104]} :
        (block_len == 5'd4)  ? {96'd0,  32'hFFFFFFFF & block[127:96]} :
        (block_len == 5'd5)  ? {88'd0,  40'hFFFFFFFFFF & block[127:88]} :
        (block_len == 5'd6)  ? {80'd0,  48'hFFFFFFFFFFFF & block[127:80]} :
        (block_len == 5'd7)  ? {72'd0,  56'hFFFFFFFFFFFFFF & block[127:72]} :
        (block_len == 5'd8)  ? {64'd0,  64'hFFFFFFFFFFFFFFFF & block[127:64]} :
        (block_len == 5'd9)  ? {56'd0,  72'hFFFFFFFFFFFFFFFFFF & block[127:56]} :
        (block_len == 5'd10) ? {48'd0,  80'hFFFFFFFFFFFFFFFFFFFF & block[127:48]} :
        (block_len == 5'd11) ? {40'd0,  88'hFFFFFFFFFFFFFFFFFFFFFF & block[127:40]} :
        (block_len == 5'd12) ? {32'd0,  96'hFFFFFFFFFFFFFFFFFFFFFFFF & block[127:32]} :
        (block_len == 5'd13) ? {24'd0,  104'hFFFFFFFFFFFFFFFFFFFFFFFFFF & block[127:24]} :
        (block_len == 5'd14) ? {16'd0,  112'hFFFFFFFFFFFFFFFFFFFFFFFFFFFF & block[127:16]} :
        (block_len == 5'd15) ? {8'd0,   120'hFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF & block[127:8]} :
                               block;

    wire [130:0] m_val = { (block_len == 5'd16), m_masked };
    // Wait, m_masked is already little-endian from bus?
    // RFC says block bytes interpreted as LE integer.
    // So byte 0 is LSB. 
    // If block[127:0] is {byte0, byte1, ...}, then byte0 is at [127:120].
    // So hibit for block_len=1 should be at bit 8.
    // m_val = {1'b1, byte0} << 0? No.
    // Let's use a simpler mapping: 
    // reverse block bytes so index 0 is at [7:0].
    wire [127:0] block_le = brevs(block);
    wire [130:0] m_final = (block_len == 5'd16) ? {2'b0, 1'b1, block_le} :
                           (acc_m_tmp >> (128 - (block_len*8))); // complicated.
    
    // Better: just append the 0x01 byte to the LE byte stream.
    reg [128:0] m_le;
    integer j;
    always @(*) begin
        m_le = 129'd0;
        for (j=0; j<16; j=j+1) begin
            if (j < block_len)
                m_le[j*8 +: 8] = block[(15-j)*8 +: 8];
        end
        m_le[block_len*8] = 1'b1;
    end

    reg [130:0] acc_m_tmp;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state     <= S_IDLE;
            acc       <= 131'd0;
            tag_valid <= 1'b0;
        end else begin
            tag_valid <= 1'b0;
            case (state)
                S_IDLE: begin
                    if (init) begin
                        // r is key[127:0], s is key[255:128]
                        // We must interpret these bytes as LE integers.
                        // In the bus {bytes[0], bytes[1], ...}, bytes[0] is MSB.
                        // RFC: byte[0] is LSB of r.
                        r   <= brevs(key[127:0]) & 128'h0ffffffc0ffffffc0ffffffc0fffffff;
                        s   <= brevs(key[255:128]);
                        acc <= 131'd0;
                    end else if (next) begin
                        // Interpret block as LE integer (byte 0 is LSB)
                        case (block_len)
                            5'd1:  acc_m_tmp = acc + {122'd0, 1'b1, block[127:120]};
                            5'd2:  acc_m_tmp = acc + {114'd0, 1'b1, block[127:120], block[119:112]};
                            5'd3:  acc_m_tmp = acc + {106'd0, 1'b1, block[127:120], block[119:112], block[111:104]};
                            5'd4:  acc_m_tmp = acc + {98'd0,  1'b1, block[127:120], block[119:112], block[111:104], block[103:96]};
                            5'd5:  acc_m_tmp = acc + {90'd0,  1'b1, block[127:120], block[119:112], block[111:104], block[103:96], block[95:88]};
                            5'd6:  acc_m_tmp = acc + {82'd0,  1'b1, block[127:120], block[119:112], block[111:104], block[103:96], block[95:88], block[87:80]};
                            5'd7:  acc_m_tmp = acc + {74'd0,  1'b1, block[127:120], block[119:112], block[111:104], block[103:96], block[95:88], block[87:80], block[79:72]};
                            5'd8:  acc_m_tmp = acc + {66'd0,  1'b1, block[127:120], block[119:112], block[111:104], block[103:96], block[95:88], block[87:80], block[79:72], block[71:64]};
                            5'd9:  acc_m_tmp = acc + {58'd0,  1'b1, block[127:120], block[119:112], block[111:104], block[103:96], block[95:88], block[87:80], block[79:72], block[71:64], block[63:56]};
                            5'd10: acc_m_tmp = acc + {50'd0,  1'b1, block[127:120], block[119:112], block[111:104], block[103:96], block[95:88], block[87:80], block[79:72], block[71:64], block[63:56], block[55:48]};
                            5'd11: acc_m_tmp = acc + {42'd0,  1'b1, block[127:120], block[119:112], block[111:104], block[103:96], block[95:88], block[87:80], block[79:72], block[71:64], block[63:56], block[55:48], block[47:40]};
                            5'd12: acc_m_tmp = acc + {34'd0,  1'b1, block[127:120], block[119:112], block[111:104], block[103:96], block[95:88], block[87:80], block[79:72], block[71:64], block[63:56], block[55:48], block[47:40], block[39:32]};
                            5'd13: acc_m_tmp = acc + {26'd0,  1'b1, block[127:120], block[119:112], block[111:104], block[103:96], block[95:88], block[87:80], block[79:72], block[71:64], block[63:56], block[55:48], block[47:40], block[39:32], block[31:24]};
                            5'd14: acc_m_tmp = acc + {18'd0,  1'b1, block[127:120], block[119:112], block[111:104], block[103:96], block[95:88], block[87:80], block[79:72], block[71:64], block[63:56], block[55:48], block[47:40], block[39:32], block[31:24], block[23:16]};
                            5'd15: acc_m_tmp = acc + {10'd0,  1'b1, block[127:120], block[119:112], block[111:104], block[103:96], block[95:88], block[87:80], block[79:72], block[71:64], block[63:56], block[55:48], block[47:40], block[39:32], block[31:24], block[23:16], block[15:8]};
                            5'd16: acc_m_tmp = acc + {2'b0,   1'b1, brevs(block)};
                            default: acc_m_tmp = acc + {2'b0, 1'b1, brevs(block)};
                        endcase
                        mult_a <= reduce130({1'b0, acc_m_tmp});
                        mult_b <= r;
                        mult_p <= 131'd0;
                        bit_cnt <= 8'd0;
                        state   <= S_MULT;
                    end
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
                        tag       <= strict_reduce(mult_p) + s;
                        tag_valid <= 1'b1;
                    end
                    state <= S_IDLE;
                end
            endcase
        end
    end
endmodule
