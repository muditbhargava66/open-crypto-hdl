// ============================================================
//  aes_core.v — AES-256 Core (Encryption Only)
//  FIPS-197 — 14 rounds, 256-bit key
//
//  Iterative datapath: one round per clock.
//  Total latency: 16 cycles (1 load + 14 rounds + 1 output)
//
//  The core pre-expands the key on load and stores all 15
//  round keys in a register file. This avoids the on-the-fly
//  key schedule latency on each block.
//
//  Interface:
//    key[255:0]       — AES-256 key (big-endian bytes)
//    plaintext[127:0] — 128-bit block
//    load             — pulse to start encryption
//    ciphertext[127:0]— encrypted output
//    done             — pulses for one cycle when ready
// ============================================================
`default_nettype none
module aes_core (
    input  wire         clk,
    input  wire         rst_n,
    input  wire [255:0] key,
    input  wire [127:0] plaintext,
    input  wire         load,
    output reg  [127:0] ciphertext,
    output reg          done
);
    // ---- GF(2^8) multiply by 2 (xtime) ----
    function [7:0] xtime;
        input [7:0] b;
        begin
            xtime = (b[7] ? ((b << 1) ^ 8'h1b) : (b << 1));
        end
    endfunction

    // ---- GF(2^8) multiply ----
    function [7:0] gfmul;
        input [7:0] a, b;
        reg [7:0] p, aa;
        integer k;
        begin
            p = 8'h00; aa = a;
            for (k = 0; k < 8; k = k + 1) begin
                if (b[k]) p = p ^ aa;
                aa = xtime(aa);
            end
            gfmul = p;
        end
    endfunction

    // ---- SubWord (4 S-box applications) ----
    wire [7:0] sb_in [0:3];
    wire [7:0] sb_out [0:3];
    genvar gx;
    generate
        for (gx = 0; gx < 4; gx = gx + 1) begin : SBOX
            aes_sbox u_sb (.in(sb_in[gx]), .out(sb_out[gx]), .inv());
        end
    endgenerate

    // ---- Round constants ----
    function [7:0] rcon;
        input integer r;
        reg [7:0] rc;
        integer i;
        begin
            rc = 8'h01;
            for (i = 1; i < r; i = i + 1) rc = xtime(rc);
            rcon = rc;
        end
    endfunction

    // ---- State ----
    // state[row][col] — 4×4 bytes
    reg [7:0] state [0:3][0:3];
    reg [7:0] rk [0:14][0:3][0:3]; // 15 round keys, each 128-bit

    reg [3:0] phase;      // 0=idle, 1=keygen, 2..15=rounds, 16=done
    reg [3:0] rk_idx;     // which round key are we generating
    reg       busy;

    // Key schedule words — stored flat for easier manipulation
    reg [31:0] w [0:59]; // 60 words for AES-256

    integer r, c, i;

    // ---- Key expansion (combinational helper) ----
    // We do this piecemeal over multiple cycles, 1 word/cycle is too slow.
    // Instead, precompute all round keys in one cycle using generate blocks
    // for real silicon; here we use a task for simulation clarity.

    task apply_sub_bytes;
        integer tr, tc;
        reg [7:0] sb_tmp [0:255];
        begin
            // Call sbox_fwd via function
            for (tr = 0; tr < 4; tr = tr + 1)
                for (tc = 0; tc < 4; tc = tc + 1)
                    state[tr][tc] <= sbox_fwd_task(state[tr][tc]);
        end
    endtask

    function [7:0] sbox_fwd_task;
        input [7:0] x;
        reg [7:0] t [0:255];
        begin
            t[  0]=8'h63; t[  1]=8'h7c; t[  2]=8'h77; t[  3]=8'h7b; t[  4]=8'hf2; t[  5]=8'h6b; t[  6]=8'h6f; t[  7]=8'hc5;
            t[  8]=8'h30; t[  9]=8'h01; t[ 10]=8'h67; t[ 11]=8'h2b; t[ 12]=8'hfe; t[ 13]=8'hd7; t[ 14]=8'hab; t[ 15]=8'h76;
            t[ 16]=8'hca; t[ 17]=8'h82; t[ 18]=8'hc9; t[ 19]=8'h7d; t[ 20]=8'hfa; t[ 21]=8'h59; t[ 22]=8'h47; t[ 23]=8'hf0;
            t[ 24]=8'had; t[ 25]=8'hd4; t[ 26]=8'ha2; t[ 27]=8'haf; t[ 28]=8'h9c; t[ 29]=8'ha4; t[ 30]=8'h72; t[ 31]=8'hc0;
            t[ 32]=8'hb7; t[ 33]=8'hfd; t[ 34]=8'h93; t[ 35]=8'h26; t[ 36]=8'h36; t[ 37]=8'h3f; t[ 38]=8'hf7; t[ 39]=8'hcc;
            t[ 40]=8'h34; t[ 41]=8'ha5; t[ 42]=8'he5; t[ 43]=8'hf1; t[ 44]=8'h71; t[ 45]=8'hd8; t[ 46]=8'h31; t[ 47]=8'h15;
            t[ 48]=8'h04; t[ 49]=8'hc7; t[ 50]=8'h23; t[ 51]=8'hc3; t[ 52]=8'h18; t[ 53]=8'h96; t[ 54]=8'h05; t[ 55]=8'h9a;
            t[ 56]=8'h07; t[ 57]=8'h12; t[ 58]=8'h80; t[ 59]=8'he2; t[ 60]=8'heb; t[ 61]=8'h27; t[ 62]=8'hb2; t[ 63]=8'h75;
            t[ 64]=8'h09; t[ 65]=8'h83; t[ 66]=8'h2c; t[ 67]=8'h1a; t[ 68]=8'h1b; t[ 69]=8'h6e; t[ 70]=8'h5a; t[ 71]=8'ha0;
            t[ 72]=8'h52; t[ 73]=8'h3b; t[ 74]=8'hd6; t[ 75]=8'hb3; t[ 76]=8'h29; t[ 77]=8'he3; t[ 78]=8'h2f; t[ 79]=8'h84;
            t[ 80]=8'h53; t[ 81]=8'hd1; t[ 82]=8'h00; t[ 83]=8'hed; t[ 84]=8'h20; t[ 85]=8'hfc; t[ 86]=8'hb1; t[ 87]=8'h5b;
            t[ 88]=8'h6a; t[ 89]=8'hcb; t[ 90]=8'hbe; t[ 91]=8'h39; t[ 92]=8'h4a; t[ 93]=8'h4c; t[ 94]=8'h58; t[ 95]=8'hcf;
            t[ 96]=8'hd0; t[ 97]=8'hef; t[ 98]=8'haa; t[ 99]=8'hfb; t[100]=8'h43; t[101]=8'h4d; t[102]=8'h33; t[103]=8'h85;
            t[104]=8'h45; t[105]=8'hf9; t[106]=8'h02; t[107]=8'h7f; t[108]=8'h50; t[109]=8'h3c; t[110]=8'h9f; t[111]=8'ha8;
            t[112]=8'h51; t[113]=8'ha3; t[114]=8'h40; t[115]=8'h8f; t[116]=8'h92; t[117]=8'h9d; t[118]=8'h38; t[119]=8'hf5;
            t[120]=8'hbc; t[121]=8'hb6; t[122]=8'hda; t[123]=8'h21; t[124]=8'h10; t[125]=8'hff; t[126]=8'hf3; t[127]=8'hd2;
            t[128]=8'hcd; t[129]=8'h0c; t[130]=8'h13; t[131]=8'hec; t[132]=8'h5f; t[133]=8'h97; t[134]=8'h44; t[135]=8'h17;
            t[136]=8'hc4; t[137]=8'ha7; t[138]=8'h7e; t[139]=8'h3d; t[140]=8'h64; t[141]=8'h5d; t[142]=8'h19; t[143]=8'h73;
            t[144]=8'h60; t[145]=8'h81; t[146]=8'h4f; t[147]=8'hdc; t[148]=8'h22; t[149]=8'h2a; t[150]=8'h90; t[151]=8'h88;
            t[152]=8'h46; t[153]=8'hee; t[154]=8'hb8; t[155]=8'h14; t[156]=8'hde; t[157]=8'h5e; t[158]=8'h0b; t[159]=8'hdb;
            t[160]=8'he0; t[161]=8'h32; t[162]=8'h3a; t[163]=8'h0a; t[164]=8'h49; t[165]=8'h06; t[166]=8'h24; t[167]=8'h5c;
            t[168]=8'hc2; t[169]=8'hd3; t[170]=8'hac; t[171]=8'h62; t[172]=8'h91; t[173]=8'h95; t[174]=8'he4; t[175]=8'h79;
            t[176]=8'he7; t[177]=8'hc8; t[178]=8'h37; t[179]=8'h6d; t[180]=8'h8d; t[181]=8'hd5; t[182]=8'h4e; t[183]=8'ha9;
            t[184]=8'h6c; t[185]=8'h56; t[186]=8'hf4; t[187]=8'hea; t[188]=8'h65; t[189]=8'h7a; t[190]=8'hae; t[191]=8'h08;
            t[192]=8'hba; t[193]=8'h78; t[194]=8'h25; t[195]=8'h2e; t[196]=8'h1c; t[197]=8'ha6; t[198]=8'hb4; t[199]=8'hc6;
            t[200]=8'he8; t[201]=8'hdd; t[202]=8'h74; t[203]=8'h1f; t[204]=8'h4b; t[205]=8'hbd; t[206]=8'h8b; t[207]=8'h8a;
            t[208]=8'h70; t[209]=8'h3e; t[210]=8'hb5; t[211]=8'h66; t[212]=8'h48; t[213]=8'h03; t[214]=8'hf6; t[215]=8'h0e;
            t[216]=8'h61; t[217]=8'h35; t[218]=8'h57; t[219]=8'hb9; t[220]=8'h86; t[221]=8'hc1; t[222]=8'h1d; t[223]=8'h9e;
            t[224]=8'he1; t[225]=8'hf8; t[226]=8'h98; t[227]=8'h11; t[228]=8'h69; t[229]=8'hd9; t[230]=8'h8e; t[231]=8'h94;
            t[232]=8'h9b; t[233]=8'h1e; t[234]=8'h87; t[235]=8'he9; t[236]=8'hce; t[237]=8'h55; t[238]=8'h28; t[239]=8'hdf;
            t[240]=8'h8c; t[241]=8'ha1; t[242]=8'h89; t[243]=8'h0d; t[244]=8'hbf; t[245]=8'he6; t[246]=8'h42; t[247]=8'h68;
            t[248]=8'h41; t[249]=8'h99; t[250]=8'h2d; t[251]=8'h0f; t[252]=8'hb0; t[253]=8'h54; t[254]=8'hbb; t[255]=8'h16;
            sbox_fwd_task = t[x];
        end
    endfunction

    // ---- ShiftRows ----
    task apply_shift_rows;
        reg [7:0] tmp;
        begin
            // Row 1: shift left by 1
            tmp = state[1][0]; state[1][0] <= state[1][1]; state[1][1] <= state[1][2];
            state[1][2] <= state[1][3]; state[1][3] <= tmp;
            // Row 2: shift left by 2
            tmp = state[2][0]; state[2][0] <= state[2][2]; state[2][2] <= tmp;
            tmp = state[2][1]; state[2][1] <= state[2][3]; state[2][3] <= tmp;
            // Row 3: shift left by 3 (right by 1)
            tmp = state[3][3]; state[3][3] <= state[3][2]; state[3][2] <= state[3][1];
            state[3][1] <= state[3][0]; state[3][0] <= tmp;
        end
    endtask

    // ---- MixColumns ----
    task apply_mix_columns;
        integer mc;
        reg [7:0] s0,s1,s2,s3;
        begin
            for (mc = 0; mc < 4; mc = mc + 1) begin
                s0 = state[0][mc]; s1 = state[1][mc];
                s2 = state[2][mc]; s3 = state[3][mc];
                state[0][mc] <= gfmul(8'h02,s0)^gfmul(8'h03,s1)^s2^s3;
                state[1][mc] <= s0^gfmul(8'h02,s1)^gfmul(8'h03,s2)^s3;
                state[2][mc] <= s0^s1^gfmul(8'h02,s2)^gfmul(8'h03,s3);
                state[3][mc] <= gfmul(8'h03,s0)^s1^s2^gfmul(8'h02,s3);
            end
        end
    endtask

    // ---- AddRoundKey ----
    task add_round_key;
        input [3:0] rnd;
        integer ar, ac;
        begin
            for (ar = 0; ar < 4; ar = ar + 1)
                for (ac = 0; ac < 4; ac = ac + 1)
                    state[ar][ac] <= state[ar][ac] ^ rk[rnd][ar][ac];
        end
    endtask

    // ---- Key schedule expansion ----
    // Expands key[255:0] into 60 words w[0..59]
    task expand_key;
        integer ki;
        reg [31:0] temp;
        reg [7:0]  b0,b1,b2,b3,rc;
        begin
            // Load initial 8 words from key (big-endian)
            w[0] = key[255:224]; w[1] = key[223:192];
            w[2] = key[191:160]; w[3] = key[159:128];
            w[4] = key[127: 96]; w[5] = key[ 95: 64];
            w[6] = key[ 63: 32]; w[7] = key[ 31:  0];

            rc = 8'h01;
            for (ki = 8; ki < 60; ki = ki + 1) begin
                temp = w[ki-1];
                if (ki % 8 == 0) begin
                    // RotWord + SubWord + Rcon
                    temp = {temp[23:0], temp[31:24]};
                    temp = {sbox_fwd_task(temp[31:24]),
                            sbox_fwd_task(temp[23:16]),
                            sbox_fwd_task(temp[15: 8]),
                            sbox_fwd_task(temp[ 7: 0])};
                    temp = temp ^ {rc, 24'h000000};
                    rc = xtime(rc);
                end else if (ki % 8 == 4) begin
                    // SubWord only
                    temp = {sbox_fwd_task(temp[31:24]),
                            sbox_fwd_task(temp[23:16]),
                            sbox_fwd_task(temp[15: 8]),
                            sbox_fwd_task(temp[ 7: 0])};
                end
                w[ki] = w[ki-8] ^ temp;
            end

            // Store into rk[0..14]
            for (ki = 0; ki < 15; ki = ki + 1) begin
                // rk[ki][row][col] — col-major, matching FIPS-197
                rk[ki][0][0] = w[ki*4  ][31:24]; rk[ki][1][0] = w[ki*4  ][23:16];
                rk[ki][2][0] = w[ki*4  ][15: 8]; rk[ki][3][0] = w[ki*4  ][ 7: 0];
                rk[ki][0][1] = w[ki*4+1][31:24]; rk[ki][1][1] = w[ki*4+1][23:16];
                rk[ki][2][1] = w[ki*4+1][15: 8]; rk[ki][3][1] = w[ki*4+1][ 7: 0];
                rk[ki][0][2] = w[ki*4+2][31:24]; rk[ki][1][2] = w[ki*4+2][23:16];
                rk[ki][2][2] = w[ki*4+2][15: 8]; rk[ki][3][2] = w[ki*4+2][ 7: 0];
                rk[ki][0][3] = w[ki*4+3][31:24]; rk[ki][1][3] = w[ki*4+3][23:16];
                rk[ki][2][3] = w[ki*4+3][15: 8]; rk[ki][3][3] = w[ki*4+3][ 7: 0];
            end
        end
    endtask

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            phase <= 4'd0;
            busy  <= 1'b0;
            done  <= 1'b0;
        end else begin
            done <= 1'b0;

            case (phase)
                4'd0: begin // Idle
                    if (load) begin
                        // Expand key and load plaintext
                        expand_key();
                        // Load state from plaintext (col-major / FIPS-197 byte order)
                        state[0][0] <= plaintext[127:120]; state[1][0] <= plaintext[119:112];
                        state[2][0] <= plaintext[111:104]; state[3][0] <= plaintext[103: 96];
                        state[0][1] <= plaintext[ 95: 88]; state[1][1] <= plaintext[ 87: 80];
                        state[2][1] <= plaintext[ 79: 72]; state[3][1] <= plaintext[ 71: 64];
                        state[0][2] <= plaintext[ 63: 56]; state[1][2] <= plaintext[ 55: 48];
                        state[2][2] <= plaintext[ 47: 40]; state[3][2] <= plaintext[ 39: 32];
                        state[0][3] <= plaintext[ 31: 24]; state[1][3] <= plaintext[ 23: 16];
                        state[2][3] <= plaintext[ 15:  8]; state[3][3] <= plaintext[  7:  0];
                        // AddRoundKey with rk[0]
                        add_round_key(4'd0);
                        phase <= 4'd1;
                    end
                end
                4'd1, 4'd2, 4'd3, 4'd4, 4'd5, 4'd6,
                4'd7, 4'd8, 4'd9, 4'd10, 4'd11, 4'd12, 4'd13: begin
                    // Rounds 1–13: SubBytes, ShiftRows, MixColumns, AddRoundKey
                    apply_sub_bytes();
                    apply_shift_rows();
                    apply_mix_columns();
                    add_round_key(phase);
                    phase <= phase + 4'd1;
                end
                4'd14: begin
                    // Final round 14: no MixColumns
                    apply_sub_bytes();
                    apply_shift_rows();
                    add_round_key(4'd14);
                    phase <= 4'd15;
                end
                4'd15: begin
                    // Output
                    ciphertext <= {
                        state[0][0], state[1][0], state[2][0], state[3][0],
                        state[0][1], state[1][1], state[2][1], state[3][1],
                        state[0][2], state[1][2], state[2][2], state[3][2],
                        state[0][3], state[1][3], state[2][3], state[3][3]
                    };
                    done  <= 1'b1;
                    phase <= 4'd0;
                end
            endcase
        end
    end
endmodule
`default_nettype wire
