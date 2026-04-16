// ============================================================
//  aes_core.v — AES-256 Core (Encryption Only)
//  FIPS-197 — 14 rounds, 256-bit key
//
//  Area-optimized version for TinyTapeout.
//  Iterative datapath: 4 cycles for SubBytes, 4 cycles for MixColumns,
//  4 cycles for AddRoundKey, 1 cycle for ShiftRows.
//  Iterative key expansion: one 32-bit word per cycle.
//  Shared 4 S-Boxes between key expansion and SubBytes.
//  Shift-register based key storage with only shift-by-one to minimize area.
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
`ifdef FORMAL
    , output wire [2:0]   f_phase
`endif
);
    // ---- GF(2^8) multiply by 2 (xtime) ----
    function [7:0] xtime;
        input [7:0] b;
        begin
            xtime = (b[7] ? ((b << 1) ^ 8'h1b) : (b << 1));
        end
    endfunction

    // ---- State ----
    reg [7:0] state [0:3][0:3];
    reg [31:0] w [0:59]; // 60 words for AES-256, used as a rotating shift register

    // FSM States
    localparam STATE_IDLE         = 3'd0;
    localparam STATE_KEYGEN       = 3'd1;
    localparam STATE_INIT_ADDRK   = 3'd2;
    localparam STATE_SUBBYTES     = 3'd3;
    localparam STATE_SHIFTROWS    = 3'd4;
    localparam STATE_MIXCOLUMNS   = 3'd5;
    localparam STATE_ADDRK        = 3'd6;
    localparam STATE_DONE         = 3'd7;

    reg [2:0] phase;

`ifdef FORMAL
    assign f_phase = phase;
`endif
    reg [5:0] keygen_cnt;
    reg [3:0] round_cnt;
    reg [1:0] loop_cnt; // Replaces subbytes_cnt, used for 4-cycle steps
    reg [7:0] rcon_val;

    reg [31:0] new_word;

    // ---- S-Box Sharing Logic ----
    wire [7:0] sbox_in[0:3];
    wire [7:0] sbox_out[0:3];

    function [7:0] sbox_fwd_task;
        input [7:0] x;
        begin
            case (x)
                8'h00: sbox_fwd_task = 8'h63; 8'h01: sbox_fwd_task = 8'h7c;
                8'h02: sbox_fwd_task = 8'h77; 8'h03: sbox_fwd_task = 8'h7b;
                8'h04: sbox_fwd_task = 8'hf2; 8'h05: sbox_fwd_task = 8'h6b;
                8'h06: sbox_fwd_task = 8'h6f; 8'h07: sbox_fwd_task = 8'hc5;
                8'h08: sbox_fwd_task = 8'h30; 8'h09: sbox_fwd_task = 8'h01;
                8'h0a: sbox_fwd_task = 8'h67; 8'h0b: sbox_fwd_task = 8'h2b;
                8'h0c: sbox_fwd_task = 8'hfe; 8'h0d: sbox_fwd_task = 8'hd7;
                8'h0e: sbox_fwd_task = 8'hab; 8'h0f: sbox_fwd_task = 8'h76;
                8'h10: sbox_fwd_task = 8'hca; 8'h11: sbox_fwd_task = 8'h82;
                8'h12: sbox_fwd_task = 8'hc9; 8'h13: sbox_fwd_task = 8'h7d;
                8'h14: sbox_fwd_task = 8'hfa; 8'h15: sbox_fwd_task = 8'h59;
                8'h16: sbox_fwd_task = 8'h47; 8'h17: sbox_fwd_task = 8'hf0;
                8'h18: sbox_fwd_task = 8'had; 8'h19: sbox_fwd_task = 8'hd4;
                8'h1a: sbox_fwd_task = 8'ha2; 8'h1b: sbox_fwd_task = 8'haf;
                8'h1c: sbox_fwd_task = 8'h9c; 8'h1d: sbox_fwd_task = 8'ha4;
                8'h1e: sbox_fwd_task = 8'h72; 8'h1f: sbox_fwd_task = 8'hc0;
                8'h20: sbox_fwd_task = 8'hb7; 8'h21: sbox_fwd_task = 8'hfd;
                8'h22: sbox_fwd_task = 8'h93; 8'h23: sbox_fwd_task = 8'h26;
                8'h24: sbox_fwd_task = 8'h36; 8'h25: sbox_fwd_task = 8'h3f;
                8'h26: sbox_fwd_task = 8'hf7; 8'h27: sbox_fwd_task = 8'hcc;
                8'h28: sbox_fwd_task = 8'h34; 8'h29: sbox_fwd_task = 8'ha5;
                8'h2a: sbox_fwd_task = 8'he5; 8'h2b: sbox_fwd_task = 8'hf1;
                8'h2c: sbox_fwd_task = 8'h71; 8'h2d: sbox_fwd_task = 8'hd8;
                8'h2e: sbox_fwd_task = 8'h31; 8'h2f: sbox_fwd_task = 8'h15;
                8'h30: sbox_fwd_task = 8'h04; 8'h31: sbox_fwd_task = 8'hc7;
                8'h32: sbox_fwd_task = 8'h23; 8'h33: sbox_fwd_task = 8'hc3;
                8'h34: sbox_fwd_task = 8'h18; 8'h35: sbox_fwd_task = 8'h96;
                8'h36: sbox_fwd_task = 8'h05; 8'h37: sbox_fwd_task = 8'h9a;
                8'h38: sbox_fwd_task = 8'h07; 8'h39: sbox_fwd_task = 8'h12;
                8'h3a: sbox_fwd_task = 8'h80; 8'h3b: sbox_fwd_task = 8'he2;
                8'h3c: sbox_fwd_task = 8'heb; 8'h3d: sbox_fwd_task = 8'h27;
                8'h3e: sbox_fwd_task = 8'hb2; 8'h3f: sbox_fwd_task = 8'h75;
                8'h40: sbox_fwd_task = 8'h09; 8'h41: sbox_fwd_task = 8'h83;
                8'h42: sbox_fwd_task = 8'h2c; 8'h43: sbox_fwd_task = 8'h1a;
                8'h44: sbox_fwd_task = 8'h1b; 8'h45: sbox_fwd_task = 8'h6e;
                8'h46: sbox_fwd_task = 8'h5a; 8'h47: sbox_fwd_task = 8'ha0;
                8'h48: sbox_fwd_task = 8'h52; 8'h49: sbox_fwd_task = 8'h3b;
                8'h4a: sbox_fwd_task = 8'hd6; 8'h4b: sbox_fwd_task = 8'hb3;
                8'h4c: sbox_fwd_task = 8'h29; 8'h4d: sbox_fwd_task = 8'he3;
                8'h4e: sbox_fwd_task = 8'h2f; 8'h4f: sbox_fwd_task = 8'h84;
                8'h50: sbox_fwd_task = 8'h53; 8'h51: sbox_fwd_task = 8'hd1;
                8'h52: sbox_fwd_task = 8'h00; 8'h53: sbox_fwd_task = 8'hed;
                8'h54: sbox_fwd_task = 8'h20; 8'h55: sbox_fwd_task = 8'hfc;
                8'h56: sbox_fwd_task = 8'hb1; 8'h57: sbox_fwd_task = 8'h5b;
                8'h58: sbox_fwd_task = 8'h6a; 8'h59: sbox_fwd_task = 8'hcb;
                8'h5a: sbox_fwd_task = 8'hbe; 8'h5b: sbox_fwd_task = 8'h39;
                8'h5c: sbox_fwd_task = 8'h4a; 8'h5d: sbox_fwd_task = 8'h4c;
                8'h5e: sbox_fwd_task = 8'h58; 8'h5f: sbox_fwd_task = 8'hcf;
                8'h60: sbox_fwd_task = 8'hd0; 8'h61: sbox_fwd_task = 8'hef;
                8'h62: sbox_fwd_task = 8'haa; 8'h63: sbox_fwd_task = 8'hfb;
                8'h64: sbox_fwd_task = 8'h43; 8'h65: sbox_fwd_task = 8'h4d;
                8'h66: sbox_fwd_task = 8'h33; 8'h67: sbox_fwd_task = 8'h85;
                8'h68: sbox_fwd_task = 8'h45; 8'h69: sbox_fwd_task = 8'hf9;
                8'h6a: sbox_fwd_task = 8'h02; 8'h6b: sbox_fwd_task = 8'h7f;
                8'h6c: sbox_fwd_task = 8'h50; 8'h6d: sbox_fwd_task = 8'h3c;
                8'h6e: sbox_fwd_task = 8'h9f; 8'h6f: sbox_fwd_task = 8'ha8;
                8'h70: sbox_fwd_task = 8'h51; 8'h71: sbox_fwd_task = 8'ha3;
                8'h72: sbox_fwd_task = 8'h40; 8'h73: sbox_fwd_task = 8'h8f;
                8'h74: sbox_fwd_task = 8'h92; 8'h75: sbox_fwd_task = 8'h9d;
                8'h76: sbox_fwd_task = 8'h38; 8'h77: sbox_fwd_task = 8'hf5;
                8'h78: sbox_fwd_task = 8'hbc; 8'h79: sbox_fwd_task = 8'hb6;
                8'h7a: sbox_fwd_task = 8'hda; 8'h7b: sbox_fwd_task = 8'h21;
                8'h7c: sbox_fwd_task = 8'h10; 8'h7d: sbox_fwd_task = 8'hff;
                8'h7e: sbox_fwd_task = 8'hf3; 8'h7f: sbox_fwd_task = 8'hd2;
                8'h80: sbox_fwd_task = 8'hcd; 8'h81: sbox_fwd_task = 8'h0c;
                8'h82: sbox_fwd_task = 8'h13; 8'h83: sbox_fwd_task = 8'hec;
                8'h84: sbox_fwd_task = 8'h5f; 8'h85: sbox_fwd_task = 8'h97;
                8'h86: sbox_fwd_task = 8'h44; 8'h87: sbox_fwd_task = 8'h17;
                8'h88: sbox_fwd_task = 8'hc4; 8'h89: sbox_fwd_task = 8'ha7;
                8'h8a: sbox_fwd_task = 8'h7e; 8'h8b: sbox_fwd_task = 8'h3d;
                8'h8c: sbox_fwd_task = 8'h64; 8'h8d: sbox_fwd_task = 8'h5d;
                8'h8e: sbox_fwd_task = 8'h19; 8'h8f: sbox_fwd_task = 8'h73;
                8'h90: sbox_fwd_task = 8'h60; 8'h91: sbox_fwd_task = 8'h81;
                8'h92: sbox_fwd_task = 8'h4f; 8'h93: sbox_fwd_task = 8'hdc;
                8'h94: sbox_fwd_task = 8'h22; 8'h95: sbox_fwd_task = 8'h2a;
                8'h96: sbox_fwd_task = 8'h90; 8'h97: sbox_fwd_task = 8'h88;
                8'h98: sbox_fwd_task = 8'h46; 8'h99: sbox_fwd_task = 8'hee;
                8'h9a: sbox_fwd_task = 8'hb8; 8'h9b: sbox_fwd_task = 8'h14;
                8'h9c: sbox_fwd_task = 8'hde; 8'h9d: sbox_fwd_task = 8'h5e;
                8'h9e: sbox_fwd_task = 8'h0b; 8'h9f: sbox_fwd_task = 8'hdb;
                8'ha0: sbox_fwd_task = 8'he0; 8'ha1: sbox_fwd_task = 8'h32;
                8'ha2: sbox_fwd_task = 8'h3a; 8'ha3: sbox_fwd_task = 8'h0a;
                8'ha4: sbox_fwd_task = 8'h49; 8'ha5: sbox_fwd_task = 8'h06;
                8'ha6: sbox_fwd_task = 8'h24; 8'ha7: sbox_fwd_task = 8'h5c;
                8'ha8: sbox_fwd_task = 8'hc2; 8'ha9: sbox_fwd_task = 8'hd3;
                8'haa: sbox_fwd_task = 8'hac; 8'hab: sbox_fwd_task = 8'h62;
                8'hac: sbox_fwd_task = 8'h91; 8'had: sbox_fwd_task = 8'h95;
                8'hae: sbox_fwd_task = 8'he4; 8'haf: sbox_fwd_task = 8'h79;
                8'hb0: sbox_fwd_task = 8'he7; 8'hb1: sbox_fwd_task = 8'hc8;
                8'hb2: sbox_fwd_task = 8'h37; 8'hb3: sbox_fwd_task = 8'h6d;
                8'hb4: sbox_fwd_task = 8'h8d; 8'hb5: sbox_fwd_task = 8'hd5;
                8'hb6: sbox_fwd_task = 8'h4e; 8'hb7: sbox_fwd_task = 8'ha9;
                8'hb8: sbox_fwd_task = 8'h6c; 8'hb9: sbox_fwd_task = 8'h56;
                8'hba: sbox_fwd_task = 8'hf4; 8'hbb: sbox_fwd_task = 8'hea;
                8'hbc: sbox_fwd_task = 8'h65; 8'hbd: sbox_fwd_task = 8'h7a;
                8'hbe: sbox_fwd_task = 8'hae; 8'hbf: sbox_fwd_task = 8'h08;
                8'hc0: sbox_fwd_task = 8'hba; 8'hc1: sbox_fwd_task = 8'h78;
                8'hc2: sbox_fwd_task = 8'h25; 8'hc3: sbox_fwd_task = 8'h2e;
                8'hc4: sbox_fwd_task = 8'h1c; 8'hc5: sbox_fwd_task = 8'ha6;
                8'hc6: sbox_fwd_task = 8'hb4; 8'hc7: sbox_fwd_task = 8'hc6;
                8'hc8: sbox_fwd_task = 8'he8; 8'hc9: sbox_fwd_task = 8'hdd;
                8'hca: sbox_fwd_task = 8'h74; 8'hcb: sbox_fwd_task = 8'h1f;
                8'hcc: sbox_fwd_task = 8'h4b; 8'hcd: sbox_fwd_task = 8'hbd;
                8'hce: sbox_fwd_task = 8'h8b; 8'hcf: sbox_fwd_task = 8'h8a;
                8'hd0: sbox_fwd_task = 8'h70; 8'hd1: sbox_fwd_task = 8'h3e;
                8'hd2: sbox_fwd_task = 8'hb5; 8'hd3: sbox_fwd_task = 8'h66;
                8'hd4: sbox_fwd_task = 8'h48; 8'hd5: sbox_fwd_task = 8'h03;
                8'hd6: sbox_fwd_task = 8'hf6; 8'hd7: sbox_fwd_task = 8'h0e;
                8'hd8: sbox_fwd_task = 8'h61; 8'hd9: sbox_fwd_task = 8'h35;
                8'hda: sbox_fwd_task = 8'h57; 8'hdb: sbox_fwd_task = 8'hb9;
                8'hdc: sbox_fwd_task = 8'h86; 8'hdd: sbox_fwd_task = 8'hc1;
                8'hde: sbox_fwd_task = 8'h1d; 8'hdf: sbox_fwd_task = 8'h9e;
                8'he0: sbox_fwd_task = 8'he1; 8'he1: sbox_fwd_task = 8'hf8;
                8'he2: sbox_fwd_task = 8'h98; 8'he3: sbox_fwd_task = 8'h11;
                8'he4: sbox_fwd_task = 8'h69; 8'he5: sbox_fwd_task = 8'hd9;
                8'he6: sbox_fwd_task = 8'h8e; 8'he7: sbox_fwd_task = 8'h94;
                8'he8: sbox_fwd_task = 8'h9b; 8'he9: sbox_fwd_task = 8'h1e;
                8'hea: sbox_fwd_task = 8'h87; 8'heb: sbox_fwd_task = 8'he9;
                8'hec: sbox_fwd_task = 8'hce; 8'hed: sbox_fwd_task = 8'h55;
                8'hee: sbox_fwd_task = 8'h28; 8'hef: sbox_fwd_task = 8'hdf;
                8'hf0: sbox_fwd_task = 8'h8c; 8'hf1: sbox_fwd_task = 8'ha1;
                8'hf2: sbox_fwd_task = 8'h89; 8'hf3: sbox_fwd_task = 8'h0d;
                8'hf4: sbox_fwd_task = 8'hbf; 8'hf5: sbox_fwd_task = 8'he6;
                8'hf6: sbox_fwd_task = 8'h42; 8'hf7: sbox_fwd_task = 8'h68;
                8'hf8: sbox_fwd_task = 8'h41; 8'hf9: sbox_fwd_task = 8'h99;
                8'hfa: sbox_fwd_task = 8'h2d; 8'hfb: sbox_fwd_task = 8'h0f;
                8'hfc: sbox_fwd_task = 8'hb0; 8'hfd: sbox_fwd_task = 8'h54;
                8'hfe: sbox_fwd_task = 8'hbb; 8'hff: sbox_fwd_task = 8'h16;
                default: sbox_fwd_task = 8'h00;
            endcase
        end
    endfunction

    assign sbox_out[0] = sbox_fwd_task(sbox_in[0]);
    assign sbox_out[1] = sbox_fwd_task(sbox_in[1]);
    assign sbox_out[2] = sbox_fwd_task(sbox_in[2]);
    assign sbox_out[3] = sbox_fwd_task(sbox_in[3]);

    assign sbox_in[0] = (phase == STATE_SUBBYTES) ? state[0][loop_cnt] :
                        (phase == STATE_KEYGEN && keygen_cnt[2:0] == 3'd0) ? w[0][23:16] :
                        (phase == STATE_KEYGEN && keygen_cnt[2:0] == 3'd4) ? w[0][31:24] :
                        8'h00;
    assign sbox_in[1] = (phase == STATE_SUBBYTES) ? state[1][loop_cnt] :
                        (phase == STATE_KEYGEN && keygen_cnt[2:0] == 3'd0) ? w[0][15:8] :
                        (phase == STATE_KEYGEN && keygen_cnt[2:0] == 3'd4) ? w[0][23:16] :
                        8'h00;
    assign sbox_in[2] = (phase == STATE_SUBBYTES) ? state[2][loop_cnt] :
                        (phase == STATE_KEYGEN && keygen_cnt[2:0] == 3'd0) ? w[0][7:0] :
                        (phase == STATE_KEYGEN && keygen_cnt[2:0] == 3'd4) ? w[0][15:8] :
                        8'h00;
    assign sbox_in[3] = (phase == STATE_SUBBYTES) ? state[3][loop_cnt] :
                        (phase == STATE_KEYGEN && keygen_cnt[2:0] == 3'd0) ? w[0][31:24] :
                        (phase == STATE_KEYGEN && keygen_cnt[2:0] == 3'd4) ? w[0][7:0] :
                        8'h00;

    // ---- Key Expansion Logic ----
    always @(*) begin
        if (keygen_cnt[2:0] == 3'd0)
            new_word = w[7] ^ {sbox_out[0] ^ rcon_val, sbox_out[1], sbox_out[2], sbox_out[3]};
        else if (keygen_cnt[2:0] == 3'd4)
            new_word = w[7] ^ {sbox_out[0], sbox_out[1], sbox_out[2], sbox_out[3]};
        else
            new_word = w[7] ^ w[0];
    end

    // ---- Main FSM ----
    integer i;
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            phase <= STATE_IDLE;
            done  <= 1'b0;
        end else begin
            done <= 1'b0;

            case (phase)
                STATE_IDLE: begin
                    if (load) begin
                        // Load initial 8 words from key (word 0 at w[7], word 7 at w[0])
                        w[7] <= key[255:224]; w[6] <= key[223:192];
                        w[5] <= key[191:160]; w[4] <= key[159:128];
                        w[3] <= key[127: 96]; w[2] <= key[ 95: 64];
                        w[1] <= key[ 63: 32]; w[0] <= key[ 31:  0];
                        
                        // Load state
                        state[0][0] <= plaintext[127:120]; state[1][0] <= plaintext[119:112];
                        state[2][0] <= plaintext[111:104]; state[3][0] <= plaintext[103: 96];
                        state[0][1] <= plaintext[ 95: 88]; state[1][1] <= plaintext[ 87: 80];
                        state[2][1] <= plaintext[ 79: 72]; state[3][1] <= plaintext[ 71: 64];
                        state[0][2] <= plaintext[ 63: 56]; state[1][2] <= plaintext[ 55: 48];
                        state[2][2] <= plaintext[ 47: 40]; state[3][2] <= plaintext[ 39: 32];
                        state[0][3] <= plaintext[ 31: 24]; state[1][3] <= plaintext[ 23: 16];
                        state[2][3] <= plaintext[ 15:  8]; state[3][3] <= plaintext[  7:  0];

                        keygen_cnt <= 6'd8;
                        rcon_val   <= 8'h01;
                        phase      <= STATE_KEYGEN;
                    end
                end

                STATE_KEYGEN: begin
                    // Shift w and insert new word
                    for (i = 59; i > 0; i = i - 1) w[i] <= w[i-1];
                    w[0] <= new_word;

                    if (keygen_cnt[2:0] == 3'd0) rcon_val <= xtime(rcon_val);
                    
                    if (keygen_cnt == 6'd59) begin
                        phase <= STATE_INIT_ADDRK;
                        loop_cnt <= 2'd0;
                    end
                    keygen_cnt <= keygen_cnt + 6'd1;
                end

                STATE_INIT_ADDRK: begin
                    // Round 0: AddRoundKey (one word at a time)
                    state[0][loop_cnt] <= state[0][loop_cnt] ^ w[59][31:24];
                    state[1][loop_cnt] <= state[1][loop_cnt] ^ w[59][23:16];
                    state[2][loop_cnt] <= state[2][loop_cnt] ^ w[59][15: 8];
                    state[3][loop_cnt] <= state[3][loop_cnt] ^ w[59][ 7: 0];
                    
                    // Rotate w by 1
                    for (i = 59; i > 0; i = i - 1) w[i] <= w[i-1];
                    w[0] <= w[59];

                    if (loop_cnt == 2'd3) begin
                        round_cnt <= 4'd1;
                        loop_cnt  <= 2'd0;
                        phase     <= STATE_SUBBYTES;
                    end else begin
                        loop_cnt <= loop_cnt + 2'd1;
                    end
                end

                STATE_SUBBYTES: begin
                    state[0][loop_cnt] <= sbox_out[0];
                    state[1][loop_cnt] <= sbox_out[1];
                    state[2][loop_cnt] <= sbox_out[2];
                    state[3][loop_cnt] <= sbox_out[3];
                    
                    if (loop_cnt == 2'd3) begin
                        phase    <= STATE_SHIFTROWS;
                        loop_cnt <= 2'd0;
                    end else begin
                        loop_cnt <= loop_cnt + 2'd1;
                    end
                end

                STATE_SHIFTROWS: begin
                    // Row 1: shift left by 1
                    state[1][0] <= state[1][1]; state[1][1] <= state[1][2];
                    state[1][2] <= state[1][3]; state[1][3] <= state[1][0];
                    // Row 2: shift left by 2
                    state[2][0] <= state[2][2]; state[2][2] <= state[2][0];
                    state[2][1] <= state[2][3]; state[2][3] <= state[2][1];
                    // Row 3: shift left by 3 (right by 1)
                    state[3][3] <= state[3][2]; state[3][2] <= state[3][1];
                    state[3][1] <= state[3][0]; state[3][0] <= state[3][3];

                    if (round_cnt == 4'd14) begin
                        phase <= STATE_ADDRK;
                        loop_cnt <= 2'd0;
                    end else begin
                        phase <= STATE_MIXCOLUMNS;
                        loop_cnt <= 2'd0;
                    end
                end

                STATE_MIXCOLUMNS: begin
                    // Use local non-blocking update
                    state[0][loop_cnt] <= xtime(state[0][loop_cnt]) ^ xtime(state[1][loop_cnt]) ^ state[1][loop_cnt] ^ state[2][loop_cnt] ^ state[3][loop_cnt];
                    state[1][loop_cnt] <= state[0][loop_cnt] ^ xtime(state[1][loop_cnt]) ^ xtime(state[2][loop_cnt]) ^ state[2][loop_cnt] ^ state[3][loop_cnt];
                    state[2][loop_cnt] <= state[0][loop_cnt] ^ state[1][loop_cnt] ^ xtime(state[2][loop_cnt]) ^ xtime(state[3][loop_cnt]) ^ state[3][loop_cnt];
                    state[3][loop_cnt] <= xtime(state[0][loop_cnt]) ^ state[0][loop_cnt] ^ state[1][loop_cnt] ^ state[2][loop_cnt] ^ xtime(state[3][loop_cnt]);
                    
                    if (loop_cnt == 2'd3) begin
                        phase    <= STATE_ADDRK;
                        loop_cnt <= 2'd0;
                    end else begin
                        loop_cnt <= loop_cnt + 2'd1;
                    end
                end

                STATE_ADDRK: begin
                    // AddRoundKey (one word at a time)
                    state[0][loop_cnt] <= state[0][loop_cnt] ^ w[59][31:24];
                    state[1][loop_cnt] <= state[1][loop_cnt] ^ w[59][23:16];
                    state[2][loop_cnt] <= state[2][loop_cnt] ^ w[59][15: 8];
                    state[3][loop_cnt] <= state[3][loop_cnt] ^ w[59][ 7: 0];
                    
                    // Rotate w by 1
                    for (i = 59; i > 0; i = i - 1) w[i] <= w[i-1];
                    w[0] <= w[59];

                    if (loop_cnt == 2'd3) begin
                        if (round_cnt == 4'd14) phase <= STATE_DONE;
                        else begin
                            round_cnt <= round_cnt + 4'd1;
                            loop_cnt  <= 2'd0;
                            phase     <= STATE_SUBBYTES;
                        end
                    end else begin
                        loop_cnt <= loop_cnt + 2'd1;
                    end
                end

                STATE_DONE: begin
                    ciphertext <= {
                        state[0][0], state[1][0], state[2][0], state[3][0],
                        state[0][1], state[1][1], state[2][1], state[3][1],
                        state[0][2], state[1][2], state[2][2], state[3][2],
                        state[0][3], state[1][3], state[2][3], state[3][3]
                    };
                    done  <= 1'b1;
                    phase <= STATE_IDLE;
                end
                default: phase <= STATE_IDLE;
            endcase
        end
    end
endmodule
`default_nettype wire
