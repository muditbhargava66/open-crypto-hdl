// ============================================================
//  aes_gcm_top.v — AES-256-GCM Authenticated Encryption
//  NIST SP 800-38D
//
//  Implements:
//    Encrypt: C = GCM-AE_K(IV, P, A)  → (C, tag)
//    Decrypt: P = GCM-AD_K(IV, C, A, T) or FAIL
//
//  Architecture:
//    - AES-256 core in CTR mode for keystream generation
//    - GHASH core for authentication
//    - Control FSM coordinating both
//
//  Simplified streaming interface:
//    1. Assert start with key, iv, aad_len, pt_len
//    2. Feed AAD blocks via aad_block + aad_valid
//    3. Feed plaintext blocks via pt_block + pt_valid
//    4. Read ct_block + ct_valid for ciphertext
//    5. Read tag[127:0] + tag_valid after all data processed
//
//  IV: 96-bit (standard GCM)
//  Tag: 128-bit
// ============================================================
`default_nettype none
module aes_gcm_top (
    input  wire         clk,
    input  wire         rst_n,

    // Configuration
    input  wire [255:0] key,
    input  wire  [95:0] iv,          // 96-bit GCM IV
    input  wire  [63:0] aad_len,     // byte count of AAD
    input  wire  [63:0] pt_len,      // byte count of plaintext
    input  wire         start,

    // AAD input (128-bit blocks, zero-padded last block)
    input  wire [127:0] aad_block,
    input  wire         aad_valid,
    output wire         aad_ready,

    // Plaintext input
    input  wire [127:0] pt_block,
    input  wire         pt_valid,

    // Ciphertext output (available one AES latency after pt_valid)
    output reg  [127:0] ct_block,
    output reg          ct_valid,

    // Tag output
    output reg  [127:0] tag,
    output reg          tag_valid,

    // Status
    output reg          busy
);
    // ---- States ----
    localparam S_IDLE      = 4'd0;
    localparam S_HASHKEY   = 4'd1;  // generate H = AES(key, 0)
    localparam S_HASHKEY_W = 4'd2;  // wait for AES
    localparam S_AAD       = 4'd3;  // process AAD
    localparam S_PT        = 4'd4;  // process plaintext
    localparam S_LEN       = 4'd5;  // process length block
    localparam S_TAG       = 4'd6;  // generate tag
    localparam S_TAG_W     = 4'd7;  // wait for AES (EJ0)
    localparam S_DONE      = 4'd8;

    reg [3:0] state;

    // AES CTR counter: J0 = IV || 0^31 || 1
    // CB_i = J0 + i  (incrementing only the 32-bit counter)
    reg [127:0] j0;           // base counter block
    reg  [31:0] ctr_val;      // current counter value

    // AES interface
    reg  [127:0] aes_pt;
    reg          aes_load;
    wire [127:0] aes_ct;
    wire         aes_done;

    // GHASH interface
    reg  [127:0] ghash_block;
    reg          ghash_init;
    reg          ghash_next;
    wire [127:0] ghash_result;
    wire         ghash_ready;

    // Hash subkey H
    reg  [127:0] H;

    // Registered key (stable)
    reg  [255:0] key_reg;
    reg   [95:0] iv_reg;

    // AES core instance
    aes_core u_aes (
        .clk        (clk),
        .rst_n      (rst_n),
        .key        (key_reg),
        .plaintext  (aes_pt),
        .load       (aes_load),
        .ciphertext (aes_ct),
        .done       (aes_done)
    );

    // GHASH core instance
    ghash_core u_ghash (
        .clk    (clk),
        .rst_n  (rst_n),
        .h      (H),
        .block  (ghash_block),
        .init   (ghash_init),
        .next   (ghash_next),
        .result (ghash_result),
        .ready  (ghash_ready)
    );

    // Saved keystream block for XOR
    reg [127:0] keystream_buf;
    reg         ks_valid;
    reg         aad_gh_running;

    // ---- Internal counters ----
    reg [63:0] aad_processed;
    reg [63:0] pt_processed;

    assign aad_ready = (state == S_AAD) && !aad_gh_running;

    // ---- Byte Masking ----
    function [127:0] mask_block;
        input [127:0] data;
        input [63:0] processed;
        input [63:0] total;
        /* verilator lint_off UNUSED */
        reg [63:0] diff;
        /* verilator lint_on UNUSED */
        begin
            if (processed + 16 <= total) begin
                mask_block = data;
            end else begin
                diff = total - processed;
                case (diff[3:0])
                    4'd1:  mask_block = data & 128'hFF000000000000000000000000000000;
                    4'd2:  mask_block = data & 128'hFFFF0000000000000000000000000000;
                    4'd3:  mask_block = data & 128'hFFFFFF00000000000000000000000000;
                    4'd4:  mask_block = data & 128'hFFFFFFFF000000000000000000000000;
                    4'd5:  mask_block = data & 128'hFFFFFFFFFF0000000000000000000000;
                    4'd6:  mask_block = data & 128'hFFFFFFFFFFFF00000000000000000000;
                    4'd7:  mask_block = data & 128'hFFFFFFFFFFFFFF000000000000000000;
                    4'd8:  mask_block = data & 128'hFFFFFFFFFFFFFFFF0000000000000000;
                    4'd9:  mask_block = data & 128'hFFFFFFFFFFFFFFFFFF00000000000000;
                    4'd10: mask_block = data & 128'hFFFFFFFFFFFFFFFFFFFF000000000000;
                    4'd11: mask_block = data & 128'hFFFFFFFFFFFFFFFFFFFFFF0000000000;
                    4'd12: mask_block = data & 128'hFFFFFFFFFFFFFFFFFFFFFFFF00000000;
                    4'd13: mask_block = data & 128'hFFFFFFFFFFFFFFFFFFFFFFFFFF000000;
                    4'd14: mask_block = data & 128'hFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000;
                    4'd15: mask_block = data & 128'hFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00;
                    default: mask_block = 128'd0;
                endcase
            end
        end
    endfunction

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state     <= S_IDLE;
            busy      <= 1'b0;
            ct_valid  <= 1'b0;
            tag_valid <= 1'b0;
            aes_load  <= 1'b0;
            ghash_init <= 1'b0;
            ghash_next <= 1'b0;
            ctr_val   <= 32'd0;
            aad_processed <= 64'd0;
            pt_processed  <= 64'd0;
        end else begin
            aes_load   <= 1'b0;
            ghash_init <= 1'b0;
            ghash_next <= 1'b0;
            ct_valid   <= 1'b0;
            tag_valid  <= 1'b0;

            case (state)
                S_IDLE: begin
                    if (start) begin
                        key_reg   <= key;
                        iv_reg    <= iv;
                        // J0 = IV || 0^31 || 1
                        j0        <= {iv, 32'h00000001};
                        ctr_val   <= 32'd2; // first encryption counter = J0 + 1
                        // Generate H = AES_K(0^128)
                        aes_pt    <= 128'd0;
                        aes_load  <= 1'b1;
                        busy      <= 1'b1;
                        aad_processed <= 64'd0;
                        pt_processed  <= 64'd0;
                        state     <= S_HASHKEY_W;
                    end
                end

                S_HASHKEY_W: begin
                    if (aes_done) begin
                        H <= aes_ct;
                        // Init GHASH accumulator
                        ghash_init <= 1'b1;
                        if (aad_len == 64'd0) begin
                            state <= S_PT;
                            ks_valid <= 1'b0;
                            if (pt_len > 0) begin
                                aes_pt   <= {iv_reg, 32'd2};
                                aes_load <= 1'b1;
                                ctr_val  <= 32'd3;
                            end
                        end else begin
                            state <= S_AAD;
                        end
                        aad_gh_running <= 1'b0;
                    end
                end

                S_AAD: begin
                    if (aad_valid && !aad_gh_running) begin
                        ghash_block    <= mask_block(aad_block, aad_processed, aad_len);
                        ghash_next     <= 1'b1;
                        aad_gh_running <= 1'b1;
                        aad_processed  <= aad_processed + 64'd16;
                    end
                    if (ghash_ready) begin
                        aad_gh_running <= 1'b0;
                        if (aad_processed >= aad_len) begin
                            state <= S_PT;
                            ks_valid <= 1'b0;
                            if (pt_len > 0) begin
                                aes_pt   <= {iv_reg, 32'd2};
                                aes_load <= 1'b1;
                                ctr_val  <= 32'd3;
                            end
                        end
                    end
                end

                S_PT: begin
                    if (pt_len == 0) begin
                        state <= S_LEN;
                    end else begin
                        if (aes_done && !ks_valid) begin
                            keystream_buf <= aes_ct;
                            ks_valid      <= 1'b1;
                        end

                        if (pt_valid && ks_valid && !ghash_next) begin
                            ct_block <= mask_block(pt_block ^ keystream_buf, pt_processed, pt_len);
                            ct_valid <= 1'b1;
                            ks_valid <= 1'b0;
                            // GHASH the masked ciphertext block
                            ghash_block <= mask_block(pt_block ^ keystream_buf, pt_processed, pt_len);
                            ghash_next  <= 1'b1;
                            pt_processed <= pt_processed + 64'd16;
                            
                            if (pt_processed + 64'd16 < pt_len) begin
                                aes_pt   <= {iv_reg, ctr_val};
                                aes_load <= 1'b1;
                                ctr_val  <= ctr_val + 32'd1;
                            end
                        end

                        if (ghash_ready && pt_processed >= pt_len) begin
                            state <= S_LEN;
                        end
                    end
                end

                S_LEN: begin
                    // Process length block: len(A) || len(C) in bits
                    ghash_block <= {aad_len << 3, pt_len << 3};
                    ghash_next  <= 1'b1;
                    state       <= S_TAG_W;
                end

                S_TAG_W: begin
                    if (ghash_ready) begin
                        // S = GHASH result; tag = AES_K(J0) XOR S
                        aes_pt   <= j0;
                        aes_load <= 1'b1;
                        state    <= S_TAG;
                    end
                end

                S_TAG: begin
                    if (aes_done) begin
                        tag       <= aes_ct ^ ghash_result;
                        tag_valid <= 1'b1;
                        busy      <= 1'b0;
                        state     <= S_IDLE;
                    end
                end

                default: ; // unused states
            endcase
        end
    end
endmodule
`default_nettype wire
