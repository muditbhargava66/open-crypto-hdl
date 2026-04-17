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
        reg [130:0] v_sub;
        /* verilator lint_on UNUSED */
        begin
            // First pass reduction
            v1 = {1'b0, val[129:0]} + ({130'd0, val[130]} * 3'd5);
            // Second pass: if v1 >= 2^130-5, subtract 2^130-5
            // 2^130-5 is 131'h3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFB
            if (v1 >= 131'h3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFB) begin
                v_sub = v1 - 131'h3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFB;
                strict_reduce = v_sub[129:0];
            end else begin
                strict_reduce = v1[129:0];
            end
        end
    endfunction

    wire [127:0] block_le = brevs(block);

    reg [128:0] padded_block;
    always @(*) begin
        case (block_len)
            5'd1:  padded_block = {121'd1, block_le[7:0]};
            5'd2:  padded_block = {113'd1, block_le[15:0]};
            5'd3:  padded_block = {105'd1, block_le[23:0]};
            5'd4:  padded_block = {97'd1,  block_le[31:0]};
            5'd5:  padded_block = {89'd1,  block_le[39:0]};
            5'd6:  padded_block = {81'd1,  block_le[47:0]};
            5'd7:  padded_block = {73'd1,  block_le[55:0]};
            5'd8:  padded_block = {65'd1,  block_le[63:0]};
            5'd9:  padded_block = {57'd1,  block_le[71:0]};
            5'd10: padded_block = {49'd1,  block_le[79:0]};
            5'd11: padded_block = {41'd1,  block_le[87:0]};
            5'd12: padded_block = {33'd1,  block_le[95:0]};
            5'd13: padded_block = {25'd1,  block_le[103:0]};
            5'd14: padded_block = {17'd1,  block_le[111:0]};
            5'd15: padded_block = {9'd1,   block_le[119:0]};
            5'd16: padded_block = {1'b1,   block_le[127:0]};
            default: padded_block = {1'b1, block_le[127:0]};
        endcase
    end

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
                        acc   <= reduce130({1'b0, acc} + {2'd0, padded_block});
                        state <= S_PRE_MULT;
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
