// ============================================================
//  des_core.v — DES Block Cipher (FIPS 46-3)
//
//  Full 16-round Feistel with:
//    IP / IP^-1 permutations
//    PC1 / PC2 key permutations
//    16 subkey expansion
//    8 S-boxes (4-bit output each)
//    P-box permutation in f()
//    E expansion in f()
//
//  Iterative: 1 round per cycle → 18-cycle total latency
//  (2 for load/output + 16 rounds)
//
//  encrypt=1 → encrypt, encrypt=0 → decrypt (reverse subkey order)
// ============================================================
`default_nettype none
module des_core (
    input  wire        clk,
    input  wire        rst_n,
    input  wire [63:0] block,      // 64-bit plaintext/ciphertext
    input  wire [63:0] key,        // 64-bit key (8 parity bits ignored)
    input  wire        encrypt,    // 1=encrypt, 0=decrypt
    input  wire        load,       // start pulse
    output reg  [63:0] result,
    output reg         done
);
    // ============================================================
    // PC1: 64-bit key → 56-bit (C0||D0)
    // ============================================================
    /* verilator lint_off UNUSED */
    function [55:0] pc1;
        input [63:0] k;
        begin
            pc1 = {
                k[64-57], k[64-49], k[64-41], k[64-33], k[64-25], k[64-17], k[64-9],
                k[64- 1], k[64-58], k[64-50], k[64-42], k[64-34], k[64-26], k[64-18],
                k[64-10], k[64- 2], k[64-59], k[64-51], k[64-43], k[64-35], k[64-27],
                k[64-19], k[64-11], k[64- 3], k[64-60], k[64-52], k[64-44], k[64-36],
                k[64-63], k[64-55], k[64-47], k[64-39], k[64-31], k[64-23], k[64-15],
                k[64- 7], k[64-62], k[64-54], k[64-46], k[64-38], k[64-30], k[64-22],
                k[64-14], k[64- 6], k[64-61], k[64-53], k[64-45], k[64-37], k[64-29],
                k[64-21], k[64-13], k[64- 5], k[64-28], k[64-20], k[64-12], k[64- 4]
            };
        end
    endfunction

    function [47:0] pc2;
        input [55:0] cd;
        begin
            pc2 = {
                cd[56-14], cd[56-17], cd[56-11], cd[56- 24], cd[56- 1], cd[56- 5],
                cd[56- 3], cd[56-28], cd[56-15], cd[56-  6], cd[56-21], cd[56-10],
                cd[56-23], cd[56-19], cd[56-12], cd[56-  4], cd[56-26], cd[56- 8],
                cd[56-16], cd[56- 7], cd[56-27], cd[56- 20], cd[56-13], cd[56- 2],
                cd[56-41], cd[56-52], cd[56-31], cd[56- 37], cd[56-47], cd[56-55],
                cd[56-30], cd[56-40], cd[56-51], cd[56- 45], cd[56-33], cd[56-48],
                cd[56-44], cd[56-49], cd[56-39], cd[56- 56], cd[56-34], cd[56-53],
                cd[56-46], cd[56-42], cd[56-50], cd[56- 36], cd[56-29], cd[56-32]
            };
        end
    endfunction
    /* verilator lint_on UNUSED */

    // ============================================================
    // IP: Initial Permutation
    // ============================================================
    function [63:0] ip;
        input [63:0] b;
        begin
            ip = {
                b[64-58], b[64-50], b[64-42], b[64-34], b[64-26], b[64-18], b[64-10], b[64-2],
                b[64-60], b[64-52], b[64-44], b[64-36], b[64-28], b[64-20], b[64-12], b[64-4],
                b[64-62], b[64-54], b[64-46], b[64-38], b[64-30], b[64-22], b[64-14], b[64-6],
                b[64-64], b[64-56], b[64-48], b[64-40], b[64-32], b[64-24], b[64-16], b[64-8],
                b[64-57], b[64-49], b[64-41], b[64-33], b[64-25], b[64-17], b[64- 9], b[64-1],
                b[64-59], b[64-51], b[64-43], b[64-35], b[64-27], b[64-19], b[64-11], b[64-3],
                b[64-61], b[64-53], b[64-45], b[64-37], b[64-29], b[64-21], b[64-13], b[64-5],
                b[64-63], b[64-55], b[64-47], b[64-39], b[64-31], b[64-23], b[64-15], b[64-7]
            };
        end
    endfunction

    // ============================================================
    // IP_INV: Final Permutation (IP^-1)
    // ============================================================
    function [63:0] ip_inv;
        input [63:0] b;
        begin
            ip_inv = {
                b[64-40], b[64- 8], b[64-48], b[64-16], b[64-56], b[64-24], b[64-64], b[64-32],
                b[64-39], b[64- 7], b[64-47], b[64-15], b[64-55], b[64-23], b[64-63], b[64-31],
                b[64-38], b[64- 6], b[64-46], b[64-14], b[64-54], b[64-22], b[64-62], b[64-30],
                b[64-37], b[64- 5], b[64-45], b[64-13], b[64-53], b[64-21], b[64-61], b[64-29],
                b[64-36], b[64- 4], b[64-44], b[64-12], b[64-52], b[64-20], b[64-60], b[64-28],
                b[64-35], b[64- 3], b[64-43], b[64-11], b[64-51], b[64-19], b[64-59], b[64-27],
                b[64-34], b[64- 2], b[64-42], b[64-10], b[64-50], b[64-18], b[64-58], b[64-26],
                b[64-33], b[64- 1], b[64-41], b[64- 9], b[64-49], b[64-17], b[64-57], b[64-25]
            };
        end
    endfunction

    // ============================================================
    // E Expansion: 32-bit → 48-bit
    // ============================================================
    function [47:0] e_expand;
        input [31:0] r;
        begin
            e_expand = {
                r[32-32], r[32- 1], r[32- 2], r[32- 3], r[32- 4], r[32- 5],
                r[32- 4], r[32- 5], r[32- 6], r[32- 7], r[32- 8], r[32- 9],
                r[32- 8], r[32- 9], r[32-10], r[32-11], r[32-12], r[32-13],
                r[32-12], r[32-13], r[32-14], r[32-15], r[32-16], r[32-17],
                r[32-16], r[32-17], r[32-18], r[32-19], r[32-20], r[32-21],
                r[32-20], r[32-21], r[32-22], r[32-23], r[32-24], r[32-25],
                r[32-24], r[32-25], r[32-26], r[32-27], r[32-28], r[32-29],
                r[32-28], r[32-29], r[32-30], r[32-31], r[32-32], r[32- 1]
            };
        end
    endfunction

    // ============================================================
    // S-Boxes
    // ============================================================
    function [3:0] sbox1; input [5:0] x;   begin
        case ({x[5],x[0],x[4:1]})
            6'd0: sbox1 = 4'd14;
            6'd1: sbox1 = 4'd4;
            6'd2: sbox1 = 4'd13;
            6'd3: sbox1 = 4'd1;
            6'd4: sbox1 = 4'd2;
            6'd5: sbox1 = 4'd15;
            6'd6: sbox1 = 4'd11;
            6'd7: sbox1 = 4'd8;
            6'd8: sbox1 = 4'd3;
            6'd9: sbox1 = 4'd10;
            6'd10: sbox1 = 4'd6;
            6'd11: sbox1 = 4'd12;
            6'd12: sbox1 = 4'd5;
            6'd13: sbox1 = 4'd9;
            6'd14: sbox1 = 4'd0;
            6'd15: sbox1 = 4'd7;
            6'd16: sbox1 = 4'd0;
            6'd17: sbox1 = 4'd15;
            6'd18: sbox1 = 4'd7;
            6'd19: sbox1 = 4'd4;
            6'd20: sbox1 = 4'd14;
            6'd21: sbox1 = 4'd2;
            6'd22: sbox1 = 4'd13;
            6'd23: sbox1 = 4'd1;
            6'd24: sbox1 = 4'd10;
            6'd25: sbox1 = 4'd6;
            6'd26: sbox1 = 4'd12;
            6'd27: sbox1 = 4'd11;
            6'd28: sbox1 = 4'd9;
            6'd29: sbox1 = 4'd5;
            6'd30: sbox1 = 4'd3;
            6'd31: sbox1 = 4'd8;
            6'd32: sbox1 = 4'd4;
            6'd33: sbox1 = 4'd1;
            6'd34: sbox1 = 4'd14;
            6'd35: sbox1 = 4'd8;
            6'd36: sbox1 = 4'd13;
            6'd37: sbox1 = 4'd6;
            6'd38: sbox1 = 4'd2;
            6'd39: sbox1 = 4'd11;
            6'd40: sbox1 = 4'd15;
            6'd41: sbox1 = 4'd12;
            6'd42: sbox1 = 4'd9;
            6'd43: sbox1 = 4'd7;
            6'd44: sbox1 = 4'd3;
            6'd45: sbox1 = 4'd10;
            6'd46: sbox1 = 4'd5;
            6'd47: sbox1 = 4'd0;
            6'd48: sbox1 = 4'd15;
            6'd49: sbox1 = 4'd12;
            6'd50: sbox1 = 4'd8;
            6'd51: sbox1 = 4'd2;
            6'd52: sbox1 = 4'd4;
            6'd53: sbox1 = 4'd9;
            6'd54: sbox1 = 4'd1;
            6'd55: sbox1 = 4'd7;
            6'd56: sbox1 = 4'd5;
            6'd57: sbox1 = 4'd11;
            6'd58: sbox1 = 4'd3;
            6'd59: sbox1 = 4'd14;
            6'd60: sbox1 = 4'd10;
            6'd61: sbox1 = 4'd0;
            6'd62: sbox1 = 4'd6;
            6'd63: sbox1 = 4'd13;
        endcase
    end  endfunction

    function [3:0] sbox2; input [5:0] x;   begin
        case ({x[5],x[0],x[4:1]})
            6'd0: sbox2 = 4'd15;
            6'd1: sbox2 = 4'd1;
            6'd2: sbox2 = 4'd8;
            6'd3: sbox2 = 4'd14;
            6'd4: sbox2 = 4'd6;
            6'd5: sbox2 = 4'd11;
            6'd6: sbox2 = 4'd3;
            6'd7: sbox2 = 4'd4;
            6'd8: sbox2 = 4'd9;
            6'd9: sbox2 = 4'd7;
            6'd10: sbox2 = 4'd2;
            6'd11: sbox2 = 4'd13;
            6'd12: sbox2 = 4'd12;
            6'd13: sbox2 = 4'd0;
            6'd14: sbox2 = 4'd5;
            6'd15: sbox2 = 4'd10;
            6'd16: sbox2 = 4'd3;
            6'd17: sbox2 = 4'd13;
            6'd18: sbox2 = 4'd4;
            6'd19: sbox2 = 4'd7;
            6'd20: sbox2 = 4'd15;
            6'd21: sbox2 = 4'd2;
            6'd22: sbox2 = 4'd8;
            6'd23: sbox2 = 4'd14;
            6'd24: sbox2 = 4'd12;
            6'd25: sbox2 = 4'd0;
            6'd26: sbox2 = 4'd1;
            6'd27: sbox2 = 4'd10;
            6'd28: sbox2 = 4'd6;
            6'd29: sbox2 = 4'd9;
            6'd30: sbox2 = 4'd11;
            6'd31: sbox2 = 4'd5;
            6'd32: sbox2 = 4'd0;
            6'd33: sbox2 = 4'd14;
            6'd34: sbox2 = 4'd7;
            6'd35: sbox2 = 4'd11;
            6'd36: sbox2 = 4'd10;
            6'd37: sbox2 = 4'd4;
            6'd38: sbox2 = 4'd13;
            6'd39: sbox2 = 4'd1;
            6'd40: sbox2 = 4'd5;
            6'd41: sbox2 = 4'd8;
            6'd42: sbox2 = 4'd12;
            6'd43: sbox2 = 4'd6;
            6'd44: sbox2 = 4'd9;
            6'd45: sbox2 = 4'd3;
            6'd46: sbox2 = 4'd2;
            6'd47: sbox2 = 4'd15;
            6'd48: sbox2 = 4'd13;
            6'd49: sbox2 = 4'd8;
            6'd50: sbox2 = 4'd10;
            6'd51: sbox2 = 4'd1;
            6'd52: sbox2 = 4'd3;
            6'd53: sbox2 = 4'd15;
            6'd54: sbox2 = 4'd4;
            6'd55: sbox2 = 4'd2;
            6'd56: sbox2 = 4'd11;
            6'd57: sbox2 = 4'd6;
            6'd58: sbox2 = 4'd7;
            6'd59: sbox2 = 4'd12;
            6'd60: sbox2 = 4'd0;
            6'd61: sbox2 = 4'd5;
            6'd62: sbox2 = 4'd14;
            6'd63: sbox2 = 4'd9;
        endcase
    end  endfunction

    function [3:0] sbox3; input [5:0] x;   begin
        case ({x[5],x[0],x[4:1]})
            6'd0: sbox3 = 4'd10;
            6'd1: sbox3 = 4'd0;
            6'd2: sbox3 = 4'd9;
            6'd3: sbox3 = 4'd14;
            6'd4: sbox3 = 4'd6;
            6'd5: sbox3 = 4'd3;
            6'd6: sbox3 = 4'd15;
            6'd7: sbox3 = 4'd5;
            6'd8: sbox3 = 4'd1;
            6'd9: sbox3 = 4'd13;
            6'd10: sbox3 = 4'd12;
            6'd11: sbox3 = 4'd7;
            6'd12: sbox3 = 4'd11;
            6'd13: sbox3 = 4'd4;
            6'd14: sbox3 = 4'd2;
            6'd15: sbox3 = 4'd8;
            6'd16: sbox3 = 4'd13;
            6'd17: sbox3 = 4'd7;
            6'd18: sbox3 = 4'd0;
            6'd19: sbox3 = 4'd9;
            6'd20: sbox3 = 4'd3;
            6'd21: sbox3 = 4'd4;
            6'd22: sbox3 = 4'd6;
            6'd23: sbox3 = 4'd10;
            6'd24: sbox3 = 4'd2;
            6'd25: sbox3 = 4'd8;
            6'd26: sbox3 = 4'd5;
            6'd27: sbox3 = 4'd14;
            6'd28: sbox3 = 4'd12;
            6'd29: sbox3 = 4'd11;
            6'd30: sbox3 = 4'd15;
            6'd31: sbox3 = 4'd1;
            6'd32: sbox3 = 4'd13;
            6'd33: sbox3 = 4'd6;
            6'd34: sbox3 = 4'd4;
            6'd35: sbox3 = 4'd9;
            6'd36: sbox3 = 4'd8;
            6'd37: sbox3 = 4'd15;
            6'd38: sbox3 = 4'd3;
            6'd39: sbox3 = 4'd0;
            6'd40: sbox3 = 4'd11;
            6'd41: sbox3 = 4'd1;
            6'd42: sbox3 = 4'd2;
            6'd43: sbox3 = 4'd12;
            6'd44: sbox3 = 4'd5;
            6'd45: sbox3 = 4'd10;
            6'd46: sbox3 = 4'd14;
            6'd47: sbox3 = 4'd7;
            6'd48: sbox3 = 4'd1;
            6'd49: sbox3 = 4'd10;
            6'd50: sbox3 = 4'd13;
            6'd51: sbox3 = 4'd0;
            6'd52: sbox3 = 4'd6;
            6'd53: sbox3 = 4'd9;
            6'd54: sbox3 = 4'd8;
            6'd55: sbox3 = 4'd7;
            6'd56: sbox3 = 4'd4;
            6'd57: sbox3 = 4'd15;
            6'd58: sbox3 = 4'd14;
            6'd59: sbox3 = 4'd3;
            6'd60: sbox3 = 4'd11;
            6'd61: sbox3 = 4'd5;
            6'd62: sbox3 = 4'd2;
            6'd63: sbox3 = 4'd12;
        endcase
    end  endfunction

    function [3:0] sbox4; input [5:0] x;   begin
        case ({x[5],x[0],x[4:1]})
            6'd0: sbox4 = 4'd7;
            6'd1: sbox4 = 4'd13;
            6'd2: sbox4 = 4'd14;
            6'd3: sbox4 = 4'd3;
            6'd4: sbox4 = 4'd0;
            6'd5: sbox4 = 4'd6;
            6'd6: sbox4 = 4'd9;
            6'd7: sbox4 = 4'd10;
            6'd8: sbox4 = 4'd1;
            6'd9: sbox4 = 4'd2;
            6'd10: sbox4 = 4'd8;
            6'd11: sbox4 = 4'd5;
            6'd12: sbox4 = 4'd11;
            6'd13: sbox4 = 4'd12;
            6'd14: sbox4 = 4'd4;
            6'd15: sbox4 = 4'd15;
            6'd16: sbox4 = 4'd13;
            6'd17: sbox4 = 4'd8;
            6'd18: sbox4 = 4'd11;
            6'd19: sbox4 = 4'd5;
            6'd20: sbox4 = 4'd6;
            6'd21: sbox4 = 4'd15;
            6'd22: sbox4 = 4'd0;
            6'd23: sbox4 = 4'd3;
            6'd24: sbox4 = 4'd4;
            6'd25: sbox4 = 4'd7;
            6'd26: sbox4 = 4'd2;
            6'd27: sbox4 = 4'd12;
            6'd28: sbox4 = 4'd1;
            6'd29: sbox4 = 4'd10;
            6'd30: sbox4 = 4'd14;
            6'd31: sbox4 = 4'd9;
            6'd32: sbox4 = 4'd10;
            6'd33: sbox4 = 4'd6;
            6'd34: sbox4 = 4'd9;
            6'd35: sbox4 = 4'd0;
            6'd36: sbox4 = 4'd12;
            6'd37: sbox4 = 4'd11;
            6'd38: sbox4 = 4'd7;
            6'd39: sbox4 = 4'd13;
            6'd40: sbox4 = 4'd15;
            6'd41: sbox4 = 4'd1;
            6'd42: sbox4 = 4'd3;
            6'd43: sbox4 = 4'd14;
            6'd44: sbox4 = 4'd5;
            6'd45: sbox4 = 4'd2;
            6'd46: sbox4 = 4'd8;
            6'd47: sbox4 = 4'd4;
            6'd48: sbox4 = 4'd3;
            6'd49: sbox4 = 4'd15;
            6'd50: sbox4 = 4'd0;
            6'd51: sbox4 = 4'd6;
            6'd52: sbox4 = 4'd10;
            6'd53: sbox4 = 4'd1;
            6'd54: sbox4 = 4'd13;
            6'd55: sbox4 = 4'd8;
            6'd56: sbox4 = 4'd9;
            6'd57: sbox4 = 4'd4;
            6'd58: sbox4 = 4'd5;
            6'd59: sbox4 = 4'd11;
            6'd60: sbox4 = 4'd12;
            6'd61: sbox4 = 4'd7;
            6'd62: sbox4 = 4'd2;
            6'd63: sbox4 = 4'd14;
        endcase
    end  endfunction

    function [3:0] sbox5; input [5:0] x;   begin
        case ({x[5],x[0],x[4:1]})
            6'd0: sbox5 = 4'd2;
            6'd1: sbox5 = 4'd12;
            6'd2: sbox5 = 4'd4;
            6'd3: sbox5 = 4'd1;
            6'd4: sbox5 = 4'd7;
            6'd5: sbox5 = 4'd10;
            6'd6: sbox5 = 4'd11;
            6'd7: sbox5 = 4'd6;
            6'd8: sbox5 = 4'd8;
            6'd9: sbox5 = 4'd5;
            6'd10: sbox5 = 4'd3;
            6'd11: sbox5 = 4'd15;
            6'd12: sbox5 = 4'd13;
            6'd13: sbox5 = 4'd0;
            6'd14: sbox5 = 4'd14;
            6'd15: sbox5 = 4'd9;
            6'd16: sbox5 = 4'd14;
            6'd17: sbox5 = 4'd11;
            6'd18: sbox5 = 4'd2;
            6'd19: sbox5 = 4'd12;
            6'd20: sbox5 = 4'd4;
            6'd21: sbox5 = 4'd7;
            6'd22: sbox5 = 4'd13;
            6'd23: sbox5 = 4'd1;
            6'd24: sbox5 = 4'd5;
            6'd25: sbox5 = 4'd0;
            6'd26: sbox5 = 4'd15;
            6'd27: sbox5 = 4'd10;
            6'd28: sbox5 = 4'd3;
            6'd29: sbox5 = 4'd9;
            6'd30: sbox5 = 4'd8;
            6'd31: sbox5 = 4'd6;
            6'd32: sbox5 = 4'd4;
            6'd33: sbox5 = 4'd2;
            6'd34: sbox5 = 4'd1;
            6'd35: sbox5 = 4'd11;
            6'd36: sbox5 = 4'd10;
            6'd37: sbox5 = 4'd13;
            6'd38: sbox5 = 4'd7;
            6'd39: sbox5 = 4'd8;
            6'd40: sbox5 = 4'd15;
            6'd41: sbox5 = 4'd9;
            6'd42: sbox5 = 4'd12;
            6'd43: sbox5 = 4'd5;
            6'd44: sbox5 = 4'd6;
            6'd45: sbox5 = 4'd3;
            6'd46: sbox5 = 4'd0;
            6'd47: sbox5 = 4'd14;
            6'd48: sbox5 = 4'd11;
            6'd49: sbox5 = 4'd8;
            6'd50: sbox5 = 4'd12;
            6'd51: sbox5 = 4'd7;
            6'd52: sbox5 = 4'd1;
            6'd53: sbox5 = 4'd14;
            6'd54: sbox5 = 4'd2;
            6'd55: sbox5 = 4'd13;
            6'd56: sbox5 = 4'd6;
            6'd57: sbox5 = 4'd15;
            6'd58: sbox5 = 4'd0;
            6'd59: sbox5 = 4'd9;
            6'd60: sbox5 = 4'd10;
            6'd61: sbox5 = 4'd4;
            6'd62: sbox5 = 4'd5;
            6'd63: sbox5 = 4'd3;
        endcase
    end  endfunction

    function [3:0] sbox6; input [5:0] x;   begin
        case ({x[5],x[0],x[4:1]})
            6'd0: sbox6 = 4'd12;
            6'd1: sbox6 = 4'd1;
            6'd2: sbox6 = 4'd10;
            6'd3: sbox6 = 4'd15;
            6'd4: sbox6 = 4'd9;
            6'd5: sbox6 = 4'd2;
            6'd6: sbox6 = 4'd6;
            6'd7: sbox6 = 4'd8;
            6'd8: sbox6 = 4'd0;
            6'd9: sbox6 = 4'd13;
            6'd10: sbox6 = 4'd3;
            6'd11: sbox6 = 4'd4;
            6'd12: sbox6 = 4'd14;
            6'd13: sbox6 = 4'd7;
            6'd14: sbox6 = 4'd5;
            6'd15: sbox6 = 4'd11;
            6'd16: sbox6 = 4'd10;
            6'd17: sbox6 = 4'd15;
            6'd18: sbox6 = 4'd4;
            6'd19: sbox6 = 4'd2;
            6'd20: sbox6 = 4'd7;
            6'd21: sbox6 = 4'd12;
            6'd22: sbox6 = 4'd9;
            6'd23: sbox6 = 4'd5;
            6'd24: sbox6 = 4'd6;
            6'd25: sbox6 = 4'd1;
            6'd26: sbox6 = 4'd13;
            6'd27: sbox6 = 4'd14;
            6'd28: sbox6 = 4'd0;
            6'd29: sbox6 = 4'd11;
            6'd30: sbox6 = 4'd3;
            6'd31: sbox6 = 4'd8;
            6'd32: sbox6 = 4'd9;
            6'd33: sbox6 = 4'd14;
            6'd34: sbox6 = 4'd15;
            6'd35: sbox6 = 4'd5;
            6'd36: sbox6 = 4'd2;
            6'd37: sbox6 = 4'd8;
            6'd38: sbox6 = 4'd12;
            6'd39: sbox6 = 4'd3;
            6'd40: sbox6 = 4'd7;
            6'd41: sbox6 = 4'd0;
            6'd42: sbox6 = 4'd4;
            6'd43: sbox6 = 4'd10;
            6'd44: sbox6 = 4'd1;
            6'd45: sbox6 = 4'd13;
            6'd46: sbox6 = 4'd11;
            6'd47: sbox6 = 4'd6;
            6'd48: sbox6 = 4'd4;
            6'd49: sbox6 = 4'd3;
            6'd50: sbox6 = 4'd2;
            6'd51: sbox6 = 4'd12;
            6'd52: sbox6 = 4'd9;
            6'd53: sbox6 = 4'd5;
            6'd54: sbox6 = 4'd15;
            6'd55: sbox6 = 4'd10;
            6'd56: sbox6 = 4'd11;
            6'd57: sbox6 = 4'd14;
            6'd58: sbox6 = 4'd1;
            6'd59: sbox6 = 4'd7;
            6'd60: sbox6 = 4'd6;
            6'd61: sbox6 = 4'd0;
            6'd62: sbox6 = 4'd8;
            6'd63: sbox6 = 4'd13;
        endcase
    end  endfunction

    function [3:0] sbox7; input [5:0] x;   begin
        case ({x[5],x[0],x[4:1]})
            6'd0: sbox7 = 4'd4;
            6'd1: sbox7 = 4'd11;
            6'd2: sbox7 = 4'd2;
            6'd3: sbox7 = 4'd14;
            6'd4: sbox7 = 4'd15;
            6'd5: sbox7 = 4'd0;
            6'd6: sbox7 = 4'd8;
            6'd7: sbox7 = 4'd13;
            6'd8: sbox7 = 4'd3;
            6'd9: sbox7 = 4'd12;
            6'd10: sbox7 = 4'd9;
            6'd11: sbox7 = 4'd7;
            6'd12: sbox7 = 4'd5;
            6'd13: sbox7 = 4'd10;
            6'd14: sbox7 = 4'd6;
            6'd15: sbox7 = 4'd1;
            6'd16: sbox7 = 4'd13;
            6'd17: sbox7 = 4'd0;
            6'd18: sbox7 = 4'd11;
            6'd19: sbox7 = 4'd7;
            6'd20: sbox7 = 4'd4;
            6'd21: sbox7 = 4'd9;
            6'd22: sbox7 = 4'd1;
            6'd23: sbox7 = 4'd10;
            6'd24: sbox7 = 4'd14;
            6'd25: sbox7 = 4'd3;
            6'd26: sbox7 = 4'd5;
            6'd27: sbox7 = 4'd12;
            6'd28: sbox7 = 4'd2;
            6'd29: sbox7 = 4'd15;
            6'd30: sbox7 = 4'd8;
            6'd31: sbox7 = 4'd6;
            6'd32: sbox7 = 4'd1;
            6'd33: sbox7 = 4'd4;
            6'd34: sbox7 = 4'd11;
            6'd35: sbox7 = 4'd13;
            6'd36: sbox7 = 4'd12;
            6'd37: sbox7 = 4'd3;
            6'd38: sbox7 = 4'd7;
            6'd39: sbox7 = 4'd14;
            6'd40: sbox7 = 4'd10;
            6'd41: sbox7 = 4'd15;
            6'd42: sbox7 = 4'd6;
            6'd43: sbox7 = 4'd8;
            6'd44: sbox7 = 4'd0;
            6'd45: sbox7 = 4'd5;
            6'd46: sbox7 = 4'd9;
            6'd47: sbox7 = 4'd2;
            6'd48: sbox7 = 4'd6;
            6'd49: sbox7 = 4'd11;
            6'd50: sbox7 = 4'd13;
            6'd51: sbox7 = 4'd8;
            6'd52: sbox7 = 4'd1;
            6'd53: sbox7 = 4'd4;
            6'd54: sbox7 = 4'd10;
            6'd55: sbox7 = 4'd7;
            6'd56: sbox7 = 4'd9;
            6'd57: sbox7 = 4'd5;
            6'd58: sbox7 = 4'd0;
            6'd59: sbox7 = 4'd15;
            6'd60: sbox7 = 4'd14;
            6'd61: sbox7 = 4'd2;
            6'd62: sbox7 = 4'd3;
            6'd63: sbox7 = 4'd12;
        endcase
    end  endfunction

    function [3:0] sbox8; input [5:0] x;   begin
        case ({x[5],x[0],x[4:1]})
            6'd0: sbox8 = 4'd13;
            6'd1: sbox8 = 4'd2;
            6'd2: sbox8 = 4'd8;
            6'd3: sbox8 = 4'd4;
            6'd4: sbox8 = 4'd6;
            6'd5: sbox8 = 4'd15;
            6'd6: sbox8 = 4'd11;
            6'd7: sbox8 = 4'd1;
            6'd8: sbox8 = 4'd10;
            6'd9: sbox8 = 4'd9;
            6'd10: sbox8 = 4'd3;
            6'd11: sbox8 = 4'd14;
            6'd12: sbox8 = 4'd5;
            6'd13: sbox8 = 4'd0;
            6'd14: sbox8 = 4'd12;
            6'd15: sbox8 = 4'd7;
            6'd16: sbox8 = 4'd1;
            6'd17: sbox8 = 4'd15;
            6'd18: sbox8 = 4'd13;
            6'd19: sbox8 = 4'd8;
            6'd20: sbox8 = 4'd10;
            6'd21: sbox8 = 4'd3;
            6'd22: sbox8 = 4'd7;
            6'd23: sbox8 = 4'd4;
            6'd24: sbox8 = 4'd12;
            6'd25: sbox8 = 4'd5;
            6'd26: sbox8 = 4'd6;
            6'd27: sbox8 = 4'd11;
            6'd28: sbox8 = 4'd0;
            6'd29: sbox8 = 4'd14;
            6'd30: sbox8 = 4'd9;
            6'd31: sbox8 = 4'd2;
            6'd32: sbox8 = 4'd7;
            6'd33: sbox8 = 4'd11;
            6'd34: sbox8 = 4'd4;
            6'd35: sbox8 = 4'd1;
            6'd36: sbox8 = 4'd9;
            6'd37: sbox8 = 4'd12;
            6'd38: sbox8 = 4'd14;
            6'd39: sbox8 = 4'd2;
            6'd40: sbox8 = 4'd0;
            6'd41: sbox8 = 4'd6;
            6'd42: sbox8 = 4'd10;
            6'd43: sbox8 = 4'd13;
            6'd44: sbox8 = 4'd15;
            6'd45: sbox8 = 4'd3;
            6'd46: sbox8 = 4'd5;
            6'd47: sbox8 = 4'd8;
            6'd48: sbox8 = 4'd2;
            6'd49: sbox8 = 4'd1;
            6'd50: sbox8 = 4'd14;
            6'd51: sbox8 = 4'd7;
            6'd52: sbox8 = 4'd4;
            6'd53: sbox8 = 4'd10;
            6'd54: sbox8 = 4'd8;
            6'd55: sbox8 = 4'd13;
            6'd56: sbox8 = 4'd15;
            6'd57: sbox8 = 4'd12;
            6'd58: sbox8 = 4'd9;
            6'd59: sbox8 = 4'd0;
            6'd60: sbox8 = 4'd3;
            6'd61: sbox8 = 4'd5;
            6'd62: sbox8 = 4'd6;
            6'd63: sbox8 = 4'd11;
        endcase
    end  endfunction

    // ============================================================
    // P-Box permutation (32-bit)
    // ============================================================
    function [31:0] pbox;
        input [31:0] x;
        begin
            pbox = {
                x[32-16], x[32- 7], x[32-20], x[32-21], x[32-29], x[32-12], x[32-28], x[32-17],
                x[32- 1], x[32-15], x[32-23], x[32-26], x[32- 5], x[32-18], x[32-31], x[32-10],
                x[32- 2], x[32- 8], x[32-24], x[32-14], x[32-32], x[32-27], x[32- 3], x[32- 9],
                x[32-19], x[32-13], x[32-30], x[32- 6], x[32-22], x[32-11], x[32- 4], x[32-25]
            };
        end
    endfunction

    // ============================================================
    // F function: R(32-bit) × K(48-bit) → 32-bit
    // ============================================================
    function [31:0] f_func;
        input [31:0] r;
        input [47:0] k;
        reg [47:0] er_xor_k;
        reg [31:0] s_out;
        begin
            er_xor_k = e_expand(r) ^ k;
            s_out = {
                sbox1(er_xor_k[47:42]),
                sbox2(er_xor_k[41:36]),
                sbox3(er_xor_k[35:30]),
                sbox4(er_xor_k[29:24]),
                sbox5(er_xor_k[23:18]),
                sbox6(er_xor_k[17:12]),
                sbox7(er_xor_k[11: 6]),
                sbox8(er_xor_k[ 5: 0])
            };
            f_func = pbox(s_out);
        end
    endfunction

    // ============================================================
    // Left rotation amounts for key schedule
    // ============================================================
    function [4:0] rot_amt;
        input [3:0] rnd; // 0-based round index
        begin
            case (rnd)
                4'd0, 4'd1, 4'd8, 4'd15: rot_amt = 5'd1;
                default:                  rot_amt = 5'd2;
            endcase
        end
    endfunction

    // ============================================================
    // State registers
    // ============================================================
    reg [31:0] L, R;
    reg [47:0] subkeys [0:15];
    reg  [3:0] rnd_cnt;
    reg  [3:0] phase;   // 0=idle, 1=running, 2=output
    reg        enc_reg;

    // ---- Precompute all 16 subkeys ----
    /* verilator lint_off BLKSEQ */
    task gen_subkeys;
        reg [55:0] cd0;
        reg [27:0] ci, di;
        integer gi;
        reg [4:0] ra;
        begin
            cd0 = pc1(key);
            ci = cd0[55:28]; di = cd0[27:0];
            for (gi = 0; gi < 16; gi = gi + 1) begin
                ra = rot_amt(gi[3:0]);
                ci = (ra == 5'd1) ? {ci[26:0], ci[27]} : {ci[25:0], ci[27:26]};
                di = (ra == 5'd1) ? {di[26:0], di[27]} : {di[25:0], di[27:26]};
                subkeys[gi] = pc2({ci, di});
            end
        end
    endtask
    /* verilator lint_on BLKSEQ */

    // Temporaries for FSM
    reg [63:0] ip_tmp;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            phase <= 4'd0;
            done  <= 1'b0;
        end else begin
            done <= 1'b0;

            case (phase)
                4'd0: begin
                    if (load) begin
                        gen_subkeys();
                        enc_reg    <= encrypt;
                        /* verilator lint_off BLKSEQ */
                        ip_tmp      = ip(block);
                        /* verilator lint_on BLKSEQ */
                        L          <= ip_tmp[63:32];
                        R          <= ip_tmp[31:0];
                        rnd_cnt    <= 4'd0;
                        phase      <= 4'd3; // New state: wait for subkeys
                    end
                end
                4'd3: begin
                    // Subkeys are now stable in registers
                    phase <= 4'd1;
                end
                4'd1: begin
                    // One Feistel round
                    L <= R;
                    R <= L ^ f_func(R, subkeys[enc_reg ? rnd_cnt : (4'd15 - rnd_cnt)]);
                    if (rnd_cnt == 4'd15) begin
                        phase <= 4'd2;
                    end else begin
                        rnd_cnt <= rnd_cnt + 4'd1;
                    end
                end
                4'd2: begin
                    // Swap L/R then apply IP^-1
                    result <= ip_inv({R, L});
                    done   <= 1'b1;
                    phase  <= 4'd0;
                end
                default: phase <= 4'd0;
            endcase
        end
    end
endmodule
`default_nettype wire
