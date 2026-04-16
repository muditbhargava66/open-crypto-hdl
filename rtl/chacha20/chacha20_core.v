// ============================================================
//  chacha20_core.v — ChaCha20 Stream Cipher Core
//  RFC 8439 §2.3
//
//  Ultra Area-Optimized for TinyTapeout.
//  Iterative: 1 quarter-round per cycle.
//  State is stored in a shift-register/rotating bank.
// ============================================================
`default_nettype none
module chacha20_core (
    input  wire         clk,
    input  wire         rst_n,
    input  wire [255:0] key,
    input  wire  [95:0] nonce,
    input  wire  [31:0] counter,
    input  wire         valid_in,
    output reg  [511:0] keystream,
    output reg          valid_out
);
    localparam [31:0] C0 = 32'h61707865;
    localparam [31:0] C1 = 32'h3320646e;
    localparam [31:0] C2 = 32'h79622d32;
    localparam [31:0] C3 = 32'h6b206574;

    reg [31:0] s [0:15];
    reg [31:0] s0 [0:15];

    reg [7:0] step_cnt; // 0..79 (80 QRs total for 20 rounds)
    reg       running;

    // Single QR instance
    reg  [31:0] qa, qb, qc, qd;
    wire [31:0] qa_next, qb_next, qc_next, qd_next;
    chacha20_qr u_qr (.a_in(qa), .b_in(qb), .c_in(qc), .d_in(qd),
                      .a_out(qa_next), .b_out(qb_next), .c_out(qc_next), .d_out(qd_next));

    // Selection logic for iterative QR
    always @(*) begin
        // Column rounds (even rounds: 0, 2, 4...)
        // Diagonal rounds (odd rounds: 1, 3, 5...)
        // We use step_cnt[0] to alternate between column/diagonal
        if (!step_cnt[2]) begin // steps 0,1,2,3: column
             case (step_cnt[1:0])
                2'd0: begin qa=s[0]; qb=s[4]; qc=s[8];  qd=s[12]; end
                2'd1: begin qa=s[1]; qb=s[5]; qc=s[9];  qd=s[13]; end
                2'd2: begin qa=s[2]; qb=s[6]; qc=s[10]; qd=s[14]; end
                2'd3: begin qa=s[3]; qb=s[7]; qc=s[11]; qd=s[15]; end
                default: begin qa=0; qb=0; qc=0; qd=0; end
             endcase
        end else begin // steps 4,5,6,7: diagonal
             case (step_cnt[1:0])
                2'd0: begin qa=s[0]; qb=s[5]; qc=s[10]; qd=s[15]; end
                2'd1: begin qa=s[1]; qb=s[6]; qc=s[11]; qd=s[12]; end
                2'd2: begin qa=s[2]; qb=s[7]; qc=s[8];  qd=s[13]; end
                2'd3: begin qa=s[3]; qb=s[4]; qc=s[9];  qd=s[14]; end
                default: begin qa=0; qb=0; qc=0; qd=0; end
             endcase
        end
    end

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            running <= 1'b0;
            valid_out <= 1'b0;
            step_cnt <= 8'd0;
        end else begin
            valid_out <= 1'b0;
            if (valid_in && !running) begin
                s[ 0] <= C0; s0[ 0] <= C0;
                s[ 1] <= C1; s0[ 1] <= C1;
                s[ 2] <= C2; s0[ 2] <= C2;
                s[ 3] <= C3; s0[ 3] <= C3;
                s[ 4] <= {key[231:224],key[239:232],key[247:240],key[255:248]}; s0[ 4] <= {key[231:224],key[239:232],key[247:240],key[255:248]};
                s[ 5] <= {key[199:192],key[207:200],key[215:208],key[223:216]}; s0[ 5] <= {key[199:192],key[207:200],key[215:208],key[223:216]};
                s[ 6] <= {key[167:160],key[175:168],key[183:176],key[191:184]}; s0[ 6] <= {key[167:160],key[175:168],key[183:176],key[191:184]};
                s[ 7] <= {key[135:128],key[143:136],key[151:144],key[159:152]}; s0[ 7] <= {key[135:128],key[143:136],key[151:144],key[159:152]};
                s[ 8] <= {key[103: 96],key[111:104],key[119:112],key[127:120]}; s0[ 8] <= {key[103: 96],key[111:104],key[119:112],key[127:120]};
                s[ 9] <= {key[ 71: 64],key[ 79: 72],key[ 87: 80],key[ 95: 88]}; s0[ 9] <= {key[ 71: 64],key[ 79: 72],key[ 87: 80],key[ 95: 88]};
                s[10] <= {key[ 39: 32],key[ 47: 40],key[ 55: 48],key[ 63: 56]}; s0[10] <= {key[ 39: 32],key[ 47: 40],key[ 55: 48],key[ 63: 56]};
                s[11] <= {key[  7:  0],key[ 15:  8],key[ 23: 16],key[ 31: 24]}; s0[11] <= {key[  7:  0],key[ 15:  8],key[ 23: 16],key[ 31: 24]};
                s[12] <= counter; s0[12] <= counter;
                s[13] <= {nonce[71:64],nonce[79:72],nonce[87:80],nonce[95:88]}; s0[13] <= {nonce[71:64],nonce[79:72],nonce[87:80],nonce[95:88]};
                s[14] <= {nonce[39:32],nonce[47:40],nonce[55:48],nonce[63:56]}; s0[14] <= {nonce[39:32],nonce[47:40],nonce[55:48],nonce[63:56]};
                s[15] <= {nonce[ 7: 0],nonce[15: 8],nonce[23:16],nonce[31:24]}; s0[15] <= {nonce[ 7: 0],nonce[15: 8],nonce[23:16],nonce[31:24]};
                running <= 1'b1;
                step_cnt <= 8'd0;
            end else if (running) begin
                if (step_cnt < 8'd80) begin
                    // Write back QR results to s
                    if (!step_cnt[2]) begin
                        case (step_cnt[1:0])
                            2'd0: begin s[0]<=qa_next; s[4]<=qb_next; s[8]<=qc_next;  s[12]<=qd_next; end
                            2'd1: begin s[1]<=qa_next; s[5]<=qb_next; s[9]<=qc_next;  s[13]<=qd_next; end
                            2'd2: begin s[2]<=qa_next; s[6]<=qb_next; s[10]<=qc_next; s[14]<=qd_next; end
                            2'd3: begin s[3]<=qa_next; s[7]<=qb_next; s[11]<=qc_next; s[15]<=qd_next; end
                        endcase
                    end else begin
                        case (step_cnt[1:0])
                            2'd0: begin s[0]<=qa_next; s[5]<=qb_next; s[10]<=qc_next; s[15]<=qd_next; end
                            2'd1: begin s[1]<=qa_next; s[6]<=qb_next; s[11]<=qc_next; s[12]<=qd_next; end
                            2'd2: begin s[2]<=qa_next; s[7]<=qb_next; s[8]<=qc_next;  s[13]<=qd_next; end
                            2'd3: begin s[3]<=qa_next; s[4]<=qb_next; s[9]<=qc_next;  s[14]<=qd_next; end
                        endcase
                    end
                    step_cnt <= step_cnt + 8'd1;
                end else begin
                    keystream <= {
                        s[15]+s0[15], s[14]+s0[14], s[13]+s0[13], s[12]+s0[12],
                        s[11]+s0[11], s[10]+s0[10], s[ 9]+s0[ 9], s[ 8]+s0[ 8],
                        s[ 7]+s0[ 7], s[ 6]+s0[ 6], s[ 5]+s0[ 5], s[ 4]+s0[ 4],
                        s[ 3]+s0[ 3], s[ 2]+s0[ 2], s[ 1]+s0[ 1], s[ 0]+s0[ 0]
                    };
                    valid_out <= 1'b1;
                    running <= 1'b0;
                end
            end
        end
    end
endmodule
