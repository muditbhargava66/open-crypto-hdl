// ============================================================
//  poly1305_core.v — Poly1305 MAC (Area-Optimized)
//  RFC 8439 §2.5
//
//  Bit-serial implementation for TinyTapeout.
//  Processes one 128-bit block in ~132 cycles.
//
//  Arithmetic: acc = (acc + block) * r mod (2^130 - 5)
// ============================================================
`default_nettype none
module poly1305_core (
    input  wire         clk,
    input  wire         rst_n,

    // Key: r[127:0] || s[127:0]
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
    // r and s constants
    reg [127:0] r;
    reg [127:0] s;

    // 131-bit internal registers
    reg [130:0] acc;
    reg [130:0] mult_a; // (acc + m)
    reg [127:0] mult_b; // r
    reg [130:0] mult_p; // partial product / intermediate accumulator

    reg [7:0] bit_cnt;
    reg [1:0] state;
    localparam S_IDLE = 2'd0;
    localparam S_ADD  = 2'd1;
    localparam S_MULT = 2'd2;
    localparam S_DONE = 2'd3;

    assign ready = (state == S_IDLE);

    // Reduction helper: adds (q * 5) to the 130-bit value
    // Since we reduce at every shift, q is small.
    function [130:0] reduce130;
        input [131:0] val; // 132-bit input
        begin
            // val = q*2^130 + r_low
            // r_low = val[129:0], q = val[131:130]
            reduce130 = {1'b0, val[129:0]} + (val[131:130] * 3'd5);
        end
    endfunction

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state     <= S_IDLE;
            acc       <= 131'd0;
            tag_valid <= 1'b0;
            bit_cnt   <= 8'd0;
        end else begin
            tag_valid <= 1'b0;

            case (state)
                S_IDLE: begin
                    if (init) begin
                        // Clamp r per RFC 8439
                        r   <= key[127:0] & 128'h0ffffffc0ffffffc0ffffffc0fffffff;
                        s   <= key[255:128];
                        acc <= 131'd0;
                    end else if (next) begin
                        // Correct Poly1305 hibit and masking logic
                        // RFC 8439: append 0x01 byte to the message.
                        // We use a bit-mask approach for area efficiency.
                        case (block_len)
                            5'd1:  mult_a <= acc + {122'd0, 1'b1,  8'hFF & block[7:0]};
                            5'd2:  mult_a <= acc + {114'd0, 1'b1, 16'hFFFF & block[15:0]};
                            5'd3:  mult_a <= acc + {106'd0, 1'b1, 24'hFFFFFF & block[23:0]};
                            5'd4:  mult_a <= acc + {98'd0,  1'b1, 32'hFFFFFFFF & block[31:0]};
                            5'd5:  mult_a <= acc + {90'd0,  1'b1, 40'hFFFFFFFFFF & block[39:0]};
                            5'd6:  mult_a <= acc + {82'd0,  1'b1, 48'hFFFFFFFFFFFF & block[47:0]};
                            5'd7:  mult_a <= acc + {74'd0,  1'b1, 56'hFFFFFFFFFFFFFF & block[55:0]};
                            5'd8:  mult_a <= acc + {66'd0,  1'b1, 64'hFFFFFFFFFFFFFFFF & block[63:0]};
                            5'd9:  mult_a <= acc + {58'd0,  1'b1, 72'hFFFFFFFFFFFFFFFFFF & block[71:0]};
                            5'd10: mult_a <= acc + {50'd0,  1'b1, 80'hFFFFFFFFFFFFFFFFFFFF & block[79:0]};
                            5'd11: mult_a <= acc + {42'd0,  1'b1, 88'hFFFFFFFFFFFFFFFFFFFFFF & block[87:0]};
                            5'd12: mult_a <= acc + {34'd0,  1'b1, 96'hFFFFFFFFFFFFFFFFFFFFFFFF & block[95:0]};
                            5'd13: mult_a <= acc + {26'd0,  1'b1, 104'hFFFFFFFFFFFFFFFFFFFFFFFFFF & block[103:0]};
                            5'd14: mult_a <= acc + {18'd0,  1'b1, 112'hFFFFFFFFFFFFFFFFFFFFFFFFFFFF & block[111:0]};
                            5'd15: mult_a <= acc + {10'd0,  1'b1, 120'hFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF & block[119:0]};
                            5'd16: mult_a <= acc + {2'b0,   1'b1, block[127:0]};
                            default: mult_a <= acc + {2'b0, 1'b1, block[127:0]};
                        endcase
                        mult_b <= r;
                        mult_p <= 131'd0;
                        bit_cnt <= 8'd0;
                        state   <= S_MULT;
                    end
                end

                S_MULT: begin
                    // Bit-serial multiplication with reduction at each step
                    // P = (P << 1) + (bit ? mult_a : 0)
                    // We process from MSB of r to LSB
                    // To keep logic depth low, we do:
                    // P_next = P + (bit ? mult_a : 0)
                    // P_reduced = P_next mod (2^130 - 5)
                    // P_shifter = P_reduced << 1
                    
                    // Actually, LSB to MSB is easier to avoid the final shift
                    if (mult_b[0]) begin
                        // mult_p = (mult_p + mult_a) mod (2^130-5)
                        mult_p <= reduce130({1'b0, mult_p} + {1'b0, mult_a});
                    end
                    
                    // mult_a = (mult_a << 1) mod (2^130-5)
                    mult_a  <= reduce130({mult_a, 1'b0});
                    mult_b  <= {1'b0, mult_b[127:1]};
                    bit_cnt <= bit_cnt + 8'd1;

                    if (bit_cnt == 8'd127) begin
                        state <= S_DONE;
                    end
                end

                S_DONE: begin
                    acc <= mult_p;
                    if (last_block) begin
                        tag       <= mult_p[127:0] + s;
                        tag_valid <= 1'b1;
                    end
                    state <= S_IDLE;
                end
            endcase
        end
    end
endmodule
