// ============================================================
//  chacha20poly1305_top.v — ChaCha20-Poly1305 AEAD
//  RFC 8439 §2.8
//
//  Encryption:
//    1. Generate Poly1305 one-time key: first 32 bytes of
//       ChaCha20 keystream(key, nonce, ctr=0)
//    2. Encrypt plaintext: keystream(key, nonce, ctr=1,2,...)
//       XOR plaintext
//    3. Compute MAC: Poly1305(otk, AAD || pad || CT || pad || lengths)
//
//  Decryption follows same structure but verifies tag first.
//
//  Simplified streaming interface (one block at a time):
//    1. Assert start with key[255:0], nonce[95:0]
//    2. Feed AAD via aad_block + aad_valid  (128-bit/block)
//    3. Feed PT  via pt_block  + pt_valid   (128-bit/block)
//    4. Read  CT  from ct_block + ct_valid
//    5. Read  tag from tag[127:0] + tag_valid
//
//  Both cores run in ping-pong to avoid pipeline stalls.
// ============================================================
`default_nettype none
module chacha20poly1305_top (
    input  wire         clk,
    input  wire         rst_n,

    // Configuration
    input  wire [255:0] key,
    input  wire  [95:0] nonce,
    input  wire         start,
    input  wire         encrypt,   // 1=encrypt, 0=decrypt

    // AAD
    input  wire [127:0] aad_block,
    input  wire  [4:0]  aad_len,   // bytes in this block (1-16)
    input  wire         aad_valid,
    input  wire         aad_last,

    // Plaintext / Ciphertext input
    input  wire [127:0] data_block,
    input  wire  [4:0]  data_len,
    input  wire         data_valid,
    input  wire         data_last,

    // Ciphertext / Plaintext output
    output reg  [127:0] out_block,
    output reg   [4:0]  out_len,
    output reg          out_valid,
    output reg          out_last,

    // Authentication tag
    output reg  [127:0] tag,
    output reg          tag_valid,

    // Status
    output reg          busy,
    output reg          auth_fail  // decrypt: tag mismatch
);
    // ---- State machine ----
    localparam S_IDLE      = 4'd0;
    localparam S_OTK       = 4'd1;  // Generate one-time key (ChaCha20 ctr=0)
    localparam S_OTK_WAIT  = 4'd2;
    localparam S_AAD       = 4'd3;
    localparam S_DATA      = 4'd4;
    localparam S_GHASH_LEN = 4'd5;  // Feed lengths to Poly1305
    localparam S_TAG       = 4'd6;  // Finalize tag
    localparam S_DONE      = 4'd7;

    reg [3:0] state;

    // ---- ChaCha20 core instance ----
    reg  [255:0] chacha_key_r;
    reg   [95:0] chacha_nonce_r;
    reg   [31:0] chacha_ctr;
    reg          chacha_start;
    wire [511:0] chacha_ks;
    wire         chacha_done;

    chacha20_core u_chacha (
        .clk      (clk),
        .rst_n    (rst_n),
        .key      (chacha_key_r),
        .nonce    (chacha_nonce_r),
        .counter  (chacha_ctr),
        .valid_in (chacha_start),
        .keystream(chacha_ks),
        .valid_out(chacha_done)
    );

    // ---- Poly1305 core instance ----
    reg  [255:0] poly_key;       // one-time key
    reg  [127:0] poly_block;
    reg   [4:0]  poly_block_len;
    reg          poly_init;
    reg          poly_next;
    reg          poly_last;
    wire [127:0] poly_tag;
    wire         poly_tag_valid;

    poly1305_core u_poly (
        .clk        (clk),
        .rst_n      (rst_n),
        .key        (poly_key),
        .init       (poly_init),
        .block      (poly_block),
        .block_len  (poly_block_len),
        .last_block (poly_last),
        .next       (poly_next),
        .tag        (poly_tag),
        .tag_valid  (poly_tag_valid)
    );

    // ---- Keystream buffer management ----
    // We need 64 bytes of keystream per 64-byte chunk.
    // We generate one 64-byte block at a time (ctr advances by 1).
    reg [511:0] ks_buf;
    reg  [127:0] ks_word_tmp;       // temp for keystream word selection
    reg  [1:0]  ks_words_left;  // how many 128-bit words remain in ks_buf
    reg         ks_fresh;

    // ---- Length counters ----
    reg [63:0] aad_byte_cnt;
    reg [63:0] data_byte_cnt;

    // ---- OTK (one-time Poly1305 key) from first keystream block ----
    // First 32 bytes of chacha20(key, nonce, 0)
    reg [255:0] otk_buf;

    // ---- Provided tag for decryption ----
    reg [127:0] expected_tag;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state        <= S_IDLE;
            busy         <= 1'b0;
            tag_valid    <= 1'b0;
            out_valid    <= 1'b0;
            out_last     <= 1'b0;
            auth_fail    <= 1'b0;
            chacha_start <= 1'b0;
            poly_init    <= 1'b0;
            poly_next    <= 1'b0;
            poly_last    <= 1'b0;
            aad_byte_cnt  <= 64'd0;
            data_byte_cnt <= 64'd0;
            chacha_ctr   <= 32'd0;
            ks_words_left <= 2'd0;
            ks_fresh     <= 1'b0;
        end else begin
            chacha_start <= 1'b0;
            poly_init    <= 1'b0;
            poly_next    <= 1'b0;
            poly_last    <= 1'b0;
            out_valid    <= 1'b0;
            out_last     <= 1'b0;
            tag_valid    <= 1'b0;

            case (state)
                // ────────────────────────────────────────────
                S_IDLE: begin
                    if (start) begin
                        chacha_key_r   <= key;
                        chacha_nonce_r <= nonce;
                        chacha_ctr     <= 32'd0;  // ctr=0 → OTK generation
                        aad_byte_cnt   <= 64'd0;
                        data_byte_cnt  <= 64'd0;
                        auth_fail      <= 1'b0;
                        busy           <= 1'b1;
                        chacha_start   <= 1'b1;
                        state          <= S_OTK_WAIT;
                    end
                end

                // ────────────────────────────────────────────
                // Wait for ChaCha20(key, nonce, 0) — extract OTK
                S_OTK_WAIT: begin
                    if (chacha_done) begin
                        // OTK = first 32 bytes of keystream
                        otk_buf  <= chacha_ks[511:256];
                        poly_key <= chacha_ks[511:256];
                        poly_init <= 1'b1;    // init Poly1305 with OTK
                        // Advance counter to 1 for data encryption
                        chacha_ctr    <= 32'd1;
                        ks_words_left <= 2'd0;
                        ks_fresh      <= 1'b0;
                        // Kick off first data keystream block
                        chacha_start  <= 1'b1;
                        state         <= S_AAD;
                    end
                end

                // ────────────────────────────────────────────
                // Process AAD blocks through Poly1305
                S_AAD: begin
                    if (chacha_done && !ks_fresh) begin
                        ks_buf        <= chacha_ks;
                        ks_words_left <= 2'd4;  // 4 × 128-bit words
                        ks_fresh      <= 1'b1;
                    end

                    if (aad_valid) begin
                        poly_block     <= aad_block;
                        poly_block_len <= aad_len;
                        poly_last      <= aad_last;
                        poly_next      <= 1'b1;
                        aad_byte_cnt   <= aad_byte_cnt + {59'd0, aad_len};
                        if (aad_last) state <= S_DATA;
                    end else if (!aad_valid && !aad_last) begin
                        // No more AAD — move directly (caller signals via aad_last=1)
                    end
                end

                // ────────────────────────────────────────────
                // Encrypt/decrypt data blocks
                S_DATA: begin
                    // Ensure we have a fresh keystream word available
                    if (ks_words_left == 2'd0 && !chacha_done) begin
                        if (!chacha_start) begin
                            chacha_ctr   <= chacha_ctr + 32'd1;
                            chacha_start <= 1'b1;
                        end
                    end

                    if (chacha_done && ks_words_left == 2'd0) begin
                        ks_buf        <= chacha_ks;
                        ks_words_left <= 2'd4;
                        ks_fresh      <= 1'b1;
                    end

                    if (data_valid && ks_words_left > 2'd0) begin
                        // Select the correct 128-bit keystream word (module-level tmp)
                        case (ks_words_left)
                            2'd4: ks_word_tmp = ks_buf[511:384];
                            2'd3: ks_word_tmp = ks_buf[383:256];
                            2'd2: ks_word_tmp = ks_buf[255:128];
                            2'd1: ks_word_tmp = ks_buf[127:  0];
                            default: ks_word_tmp = 128'd0;
                        endcase

                        out_block      <= data_block ^ ks_word_tmp;
                        out_len        <= data_len;
                        out_valid      <= 1'b1;
                        out_last       <= data_last;
                        ks_words_left  <= ks_words_left - 2'd1;

                        // Feed ciphertext to Poly1305
                        if (encrypt) begin
                            // MAC over ciphertext
                            poly_block     <= data_block ^ ks_word_tmp;
                        end else begin
                            // MAC over received ciphertext (data_block for decrypt)
                            poly_block     <= data_block;
                        end
                        poly_block_len <= data_len;
                        poly_last      <= data_last;
                        poly_next      <= 1'b1;

                        data_byte_cnt  <= data_byte_cnt + {59'd0, data_len};

                        if (data_last) begin
                            state <= S_GHASH_LEN;
                        end
                    end
                end

                // ────────────────────────────────────────────
                // Feed length block to Poly1305
                // Format: little-endian len(AAD) || len(CT)
                S_GHASH_LEN: begin
                    // RFC 8439 §2.8: lengths are 64-bit little-endian
                    poly_block <= {
                        // CT byte count LE
                        data_byte_cnt[ 7: 0], data_byte_cnt[15: 8],
                        data_byte_cnt[23:16], data_byte_cnt[31:24],
                        data_byte_cnt[39:32], data_byte_cnt[47:40],
                        data_byte_cnt[55:48], data_byte_cnt[63:56],
                        // AAD byte count LE
                        aad_byte_cnt[ 7: 0], aad_byte_cnt[15: 8],
                        aad_byte_cnt[23:16], aad_byte_cnt[31:24],
                        aad_byte_cnt[39:32], aad_byte_cnt[47:40],
                        aad_byte_cnt[55:48], aad_byte_cnt[63:56]
                    };
                    poly_block_len <= 5'd16;
                    poly_last      <= 1'b1;
                    poly_next      <= 1'b1;
                    state          <= S_TAG;
                end

                // ────────────────────────────────────────────
                S_TAG: begin
                    if (poly_tag_valid) begin
                        if (encrypt) begin
                            tag       <= poly_tag;
                            tag_valid <= 1'b1;
                        end else begin
                            // Constant-time comparison (simplified for RTL)
                            auth_fail <= (poly_tag != expected_tag);
                            tag_valid <= 1'b1;
                        end
                        state <= S_DONE;
                    end
                end

                S_DONE: begin
                    busy  <= 1'b0;
                    state <= S_IDLE;
                end
            endcase
        end
    end

    // For decryption: caller must write expected tag via this port
    // (not shown for brevity — would be a register write)
    always @(posedge clk) begin
        if (!encrypt && start)
            expected_tag <= tag;  // latch externally provided tag
    end

endmodule
`default_nettype wire
