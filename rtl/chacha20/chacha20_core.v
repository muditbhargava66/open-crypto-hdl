// ============================================================
//  chacha20_core.v — ChaCha20 Stream Cipher Core
//  RFC 8439 §2.3
//
//  Iterative: 10 double-rounds (20 rounds total).
//  One double-round per clock cycle → 10+2 = 12-cycle latency.
//
//  Interface:
//    key   [255:0]  — 256-bit secret key
//    nonce  [95:0]  — 96-bit nonce
//    counter[31:0]  — 32-bit block counter
//    valid_in       — pulse high for one cycle to start
//    keystream[511:0]— 512-bit (64-byte) keystream block
//    valid_out      — pulses high when keystream is ready
// ============================================================
`default_nettype none
module chacha20_core (
    input  wire         clk,
    input  wire         rst_n,
    // Inputs
    input  wire [255:0] key,
    input  wire  [95:0] nonce,
    input  wire  [31:0] counter,
    input  wire         valid_in,
    // Outputs
    output reg  [511:0] keystream,
    output reg          valid_out
);
    // --- ChaCha20 constants (RFC 8439) ---
    localparam [31:0] C0 = 32'h61707865;
    localparam [31:0] C1 = 32'h3320646e;
    localparam [31:0] C2 = 32'h79622d32;
    localparam [31:0] C3 = 32'h6b206574;

    // State: 16 × 32-bit words
    reg [31:0] s [0:15];
    // Initial state snapshot for final addition
    reg [31:0] s0 [0:15];

    reg [3:0]  round_cnt;   // 0..10 (10 double-rounds + idle)
    reg        running;

    integer i;

    // Quarter-round wires (column + diagonal)
    wire [31:0] qa_out, qb_out, qc_out, qd_out;
    wire [31:0] re_out, rf_out, rg_out, rh_out;
    wire [31:0] ri_out, rj_out, rk_out, rl_out;
    wire [31:0] rm_out, rn_out, ro_out, rp_out;

    // Column QRs
    chacha20_qr qr0 (.a_in(s[ 0]),.b_in(s[ 4]),.c_in(s[ 8]),.d_in(s[12]),
                     .a_out(qa_out),.b_out(qb_out),.c_out(qc_out),.d_out(qd_out));
    chacha20_qr qr1 (.a_in(s[ 1]),.b_in(s[ 5]),.c_in(s[ 9]),.d_in(s[13]),
                     .a_out(re_out),.b_out(rf_out),.c_out(rg_out),.d_out(rh_out));
    chacha20_qr qr2 (.a_in(s[ 2]),.b_in(s[ 6]),.c_in(s[10]),.d_in(s[14]),
                     .a_out(ri_out),.b_out(rj_out),.c_out(rk_out),.d_out(rl_out));
    chacha20_qr qr3 (.a_in(s[ 3]),.b_in(s[ 7]),.c_in(s[11]),.d_in(s[15]),
                     .a_out(rm_out),.b_out(rn_out),.c_out(ro_out),.d_out(rp_out));

    // After column round, intermediate state for diagonal
    wire [31:0] mid [0:15];
    assign mid[ 0]=qa_out; assign mid[ 4]=qb_out; assign mid[ 8]=qc_out; assign mid[12]=qd_out;
    assign mid[ 1]=re_out; assign mid[ 5]=rf_out; assign mid[ 9]=rg_out; assign mid[13]=rh_out;
    assign mid[ 2]=ri_out; assign mid[ 6]=rj_out; assign mid[10]=rk_out; assign mid[14]=rl_out;
    assign mid[ 3]=rm_out; assign mid[ 7]=rn_out; assign mid[11]=ro_out; assign mid[15]=rp_out;

    // Diagonal QRs
    wire [31:0] da_out,db_out,dc_out,dd_out;
    wire [31:0] de_out,df_out,dg_out,dh_out;
    wire [31:0] di_out,dj_out,dk_out,dl_out;
    wire [31:0] dm_out,dn_out,do_out,dp_out;

    chacha20_qr dqr0 (.a_in(mid[ 0]),.b_in(mid[ 5]),.c_in(mid[10]),.d_in(mid[15]),
                      .a_out(da_out),.b_out(db_out),.c_out(dc_out),.d_out(dd_out));
    chacha20_qr dqr1 (.a_in(mid[ 1]),.b_in(mid[ 6]),.c_in(mid[11]),.d_in(mid[12]),
                      .a_out(de_out),.b_out(df_out),.c_out(dg_out),.d_out(dh_out));
    chacha20_qr dqr2 (.a_in(mid[ 2]),.b_in(mid[ 7]),.c_in(mid[ 8]),.d_in(mid[13]),
                      .a_out(di_out),.b_out(dj_out),.c_out(dk_out),.d_out(dl_out));
    chacha20_qr dqr3 (.a_in(mid[ 3]),.b_in(mid[ 4]),.c_in(mid[ 9]),.d_in(mid[14]),
                      .a_out(dm_out),.b_out(dn_out),.c_out(do_out),.d_out(dp_out));

    // After diagonal: new state
    wire [31:0] nxt [0:15];
    assign nxt[ 0]=da_out; assign nxt[ 5]=db_out; assign nxt[10]=dc_out; assign nxt[15]=dd_out;
    assign nxt[ 1]=de_out; assign nxt[ 6]=df_out; assign nxt[11]=dg_out; assign nxt[12]=dh_out;
    assign nxt[ 2]=di_out; assign nxt[ 7]=dj_out; assign nxt[ 8]=dk_out; assign nxt[13]=dl_out;
    assign nxt[ 3]=dm_out; assign nxt[ 4]=dn_out; assign nxt[ 9]=do_out; assign nxt[14]=dp_out;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            running   <= 1'b0;
            valid_out <= 1'b0;
            round_cnt <= 4'd0;
        end else begin
            valid_out <= 1'b0;

            if (valid_in && !running) begin
                // Load initial state (RFC 8439 §2.3)
                // Key and nonce are presented big-endian (byte[0] at MSB).
                // ChaCha20 state words are little-endian 32-bit words, so
                // each 4-byte group must be byte-swapped when loaded.
                s[ 0] <= C0; s[ 1] <= C1; s[ 2] <= C2; s[ 3] <= C3;
                // key[255:248]=byte[0] ... key[7:0]=byte[31]
                s[ 4] <= {key[231:224],key[239:232],key[247:240],key[255:248]}; // bytes  0-3
                s[ 5] <= {key[199:192],key[207:200],key[215:208],key[223:216]}; // bytes  4-7
                s[ 6] <= {key[167:160],key[175:168],key[183:176],key[191:184]}; // bytes  8-11
                s[ 7] <= {key[135:128],key[143:136],key[151:144],key[159:152]}; // bytes 12-15
                s[ 8] <= {key[103: 96],key[111:104],key[119:112],key[127:120]}; // bytes 16-19
                s[ 9] <= {key[ 71: 64],key[ 79: 72],key[ 87: 80],key[ 95: 88]}; // bytes 20-23
                s[10] <= {key[ 39: 32],key[ 47: 40],key[ 55: 48],key[ 63: 56]}; // bytes 24-27
                s[11] <= {key[  7:  0],key[ 15:  8],key[ 23: 16],key[ 31: 24]}; // bytes 28-31
                s[12] <= counter;
                // nonce[95:88]=byte[0] ... nonce[7:0]=byte[11]
                s[13] <= {nonce[71:64],nonce[79:72],nonce[87:80],nonce[95:88]}; // bytes 0-3
                s[14] <= {nonce[39:32],nonce[47:40],nonce[55:48],nonce[63:56]}; // bytes 4-7
                s[15] <= {nonce[ 7: 0],nonce[15: 8],nonce[23:16],nonce[31:24]}; // bytes 8-11

                s0[ 0] <= C0; s0[ 1] <= C1; s0[ 2] <= C2; s0[ 3] <= C3;
                s0[ 4] <= {key[231:224],key[239:232],key[247:240],key[255:248]};
                s0[ 5] <= {key[199:192],key[207:200],key[215:208],key[223:216]};
                s0[ 6] <= {key[167:160],key[175:168],key[183:176],key[191:184]};
                s0[ 7] <= {key[135:128],key[143:136],key[151:144],key[159:152]};
                s0[ 8] <= {key[103: 96],key[111:104],key[119:112],key[127:120]};
                s0[ 9] <= {key[ 71: 64],key[ 79: 72],key[ 87: 80],key[ 95: 88]};
                s0[10] <= {key[ 39: 32],key[ 47: 40],key[ 55: 48],key[ 63: 56]};
                s0[11] <= {key[  7:  0],key[ 15:  8],key[ 23: 16],key[ 31: 24]};
                s0[12] <= counter;
                s0[13] <= {nonce[71:64],nonce[79:72],nonce[87:80],nonce[95:88]};
                s0[14] <= {nonce[39:32],nonce[47:40],nonce[55:48],nonce[63:56]};
                s0[15] <= {nonce[ 7: 0],nonce[15: 8],nonce[23:16],nonce[31:24]};

                running   <= 1'b1;
                round_cnt <= 4'd0;
            end else if (running) begin
                if (round_cnt < 4'd10) begin
                    // Apply one double-round
                    for (i = 0; i < 16; i = i + 1)
                        s[i] <= nxt[i];
                    round_cnt <= round_cnt + 4'd1;
                end else begin
                    // Final addition and output
                    for (i = 0; i < 16; i = i + 1)
                        s[i] <= s[i] + s0[i];

                    keystream <= {
                        s[15]+s0[15], s[14]+s0[14], s[13]+s0[13], s[12]+s0[12],
                        s[11]+s0[11], s[10]+s0[10], s[ 9]+s0[ 9], s[ 8]+s0[ 8],
                        s[ 7]+s0[ 7], s[ 6]+s0[ 6], s[ 5]+s0[ 5], s[ 4]+s0[ 4],
                        s[ 3]+s0[ 3], s[ 2]+s0[ 2], s[ 1]+s0[ 1], s[ 0]+s0[ 0]
                    };
                    valid_out <= 1'b1;
                    running   <= 1'b0;
                end
            end
        end
    end
endmodule
`default_nettype wire
