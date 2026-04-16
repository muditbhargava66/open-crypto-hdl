// ============================================================
//  chacha20poly1305_top.v — ChaCha20-Poly1305 AEAD Logic
//  RFC 8439 §2.8
// ============================================================
`default_nettype none
module chacha20poly1305_top (
    input  wire         clk,
    input  wire         rst_n,

    // Configuration
    input  wire [255:0] key,
    input  wire  [95:0] nonce,
    input  wire         start,
    input  wire         encrypt,

    // AAD
    input  wire [127:0] aad_block,
    input  wire  [4:0]  aad_len,
    input  wire         aad_valid,
    input  wire         aad_last,

    // Data input
    input  wire [127:0] data_block,
    input  wire  [4:0]  data_len,
    input  wire         data_valid,
    input  wire         data_last,

    // Data output
    output reg  [127:0] out_block,
    output wire  [4:0]  out_len,
    output reg          out_valid,
    output wire         out_last,

    // Tag
    output reg  [127:0] tag,
    output reg          tag_valid,

    // Status
    output reg          busy,
    output reg          auth_fail,

    // Shared Core Interfaces
    output reg  [31:0]  chacha_ctr,
    output reg          chacha_start,
    input  wire [511:0] chacha_ks,
    input  wire         chacha_done,

    output wire [255:0] cp_otk,
    output reg  [127:0] poly_block,
    output reg  [4:0]   poly_block_len,
    output reg          poly_init,
    output reg          poly_next,
    output reg          poly_last,
    input  wire [127:0] poly_tag,
    input  wire         poly_tag_valid
);
    // OTK is the first 256 bits of the first ChaCha20 block
    assign cp_otk = chacha_ks[511:256];
    // ---- State machine ----
    localparam S_IDLE      = 4'd0;
    localparam S_OTK       = 4'd1;
    localparam S_OTK_WAIT  = 4'd2;
    localparam S_AAD       = 4'd3;
    localparam S_DATA      = 4'd4;
    localparam S_GHASH_LEN = 4'd5;
    localparam S_TAG       = 4'd6;
    localparam S_DONE      = 4'd7;

    reg [3:0] state;

    reg [511:0] ks_buf;
    wire [127:0] ks_word_sel = (ks_words_left == 3'd4) ? ks_buf[511:384] :
                               (ks_words_left == 3'd3) ? ks_buf[383:256] :
                               (ks_words_left == 3'd2) ? ks_buf[255:128] :
                               (ks_words_left == 3'd1) ? ks_buf[127:  0] : 128'd0;
    reg [2:0]   ks_words_left;
    reg         ks_fresh;

    reg [63:0] aad_byte_cnt;
    reg [63:0] data_byte_cnt;
    reg [127:0] expected_tag;

    assign out_len = data_len;
    assign out_last = data_last;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state        <= S_IDLE;
            busy         <= 1'b0;
            tag_valid    <= 1'b0;
            out_valid    <= 1'b0;
            auth_fail    <= 1'b0;
            chacha_start <= 1'b0;
            poly_init    <= 1'b0;
            poly_next    <= 1'b0;
            poly_last    <= 1'b0;
            aad_byte_cnt  <= 64'd0;
            data_byte_cnt <= 64'd0;
            chacha_ctr   <= 32'd0;
            ks_words_left <= 3'd0;
            ks_fresh     <= 1'b0;
            expected_tag <= 128'd0;
        end else begin
            chacha_start <= 1'b0;
            poly_init    <= 1'b0;
            poly_next    <= 1'b0;
            poly_last    <= 1'b0;
            out_valid    <= 1'b0;
            tag_valid    <= 1'b0;

            case (state)
                S_IDLE: begin
                    if (start) begin
                        chacha_ctr     <= 32'd0;
                        aad_byte_cnt   <= 64'd0;
                        data_byte_cnt  <= 64'd0;
                        auth_fail      <= 1'b0;
                        busy           <= 1'b1;
                        chacha_start   <= 1'b1;
                        state          <= S_OTK_WAIT;
                        if (!encrypt) expected_tag <= tag; 
                    end
                end

                S_OTK_WAIT: begin
                    if (chacha_done) begin
                        poly_init <= 1'b1;
                        chacha_ctr    <= 32'd1;
                        ks_words_left <= 3'd0;
                        ks_fresh      <= 1'b0;
                        chacha_start  <= 1'b1;
                        state         <= S_AAD;
                    end
                end

                S_AAD: begin
                    if (chacha_done && !ks_fresh) begin
                        ks_buf        <= chacha_ks;
                        ks_words_left <= 3'd4;
                        ks_fresh      <= 1'b1;
                    end
                    if (aad_valid) begin
                        poly_block     <= aad_block;
                        poly_block_len <= aad_len;
                        poly_last      <= aad_last;
                        poly_next      <= 1'b1;
                        aad_byte_cnt   <= aad_byte_cnt + {59'd0, aad_len};
                        if (aad_last) state <= S_DATA;
                    end else if (aad_last) state <= S_DATA;
                end

                S_DATA: begin
                    if (ks_words_left == 3'd0 && !chacha_done) begin
                        if (!chacha_start) begin
                            chacha_ctr   <= chacha_ctr + 32'd1;
                            chacha_start <= 1'b1;
                        end
                    end
                    if (chacha_done && ks_words_left == 3'd0) begin
                        ks_buf        <= chacha_ks;
                        ks_words_left <= 3'd4;
                        ks_fresh      <= 1'b1;
                    end
                    if (data_valid && ks_words_left > 3'd0) begin
                        out_block      <= data_block ^ ks_word_sel;
                        out_valid      <= 1'b1;
                        ks_words_left  <= ks_words_left - 3'd1;
                        poly_block     <= encrypt ? (data_block ^ ks_word_sel) : data_block;
                        poly_block_len <= data_len;
                        poly_last      <= data_last;
                        poly_next      <= 1'b1;
                        data_byte_cnt  <= data_byte_cnt + {59'd0, data_len};
                        if (data_last) state <= S_GHASH_LEN;
                    end else if (data_last && !data_valid) begin
                        state <= S_GHASH_LEN;
                    end
                end

                S_GHASH_LEN: begin
                    poly_block <= {data_byte_cnt[7:0], data_byte_cnt[15:8], data_byte_cnt[23:16], data_byte_cnt[31:24], data_byte_cnt[39:32], data_byte_cnt[47:40], data_byte_cnt[55:48], data_byte_cnt[63:56],
                                   aad_byte_cnt[7:0],  aad_byte_cnt[15:8],  aad_byte_cnt[23:16],  aad_byte_cnt[31:24],  aad_byte_cnt[39:32],  aad_byte_cnt[47:40],  aad_byte_cnt[55:48],  aad_byte_cnt[63:56]};
                    poly_block_len <= 5'd16;
                    poly_last      <= 1'b1;
                    poly_next      <= 1'b1;
                    state          <= S_TAG;
                end

                S_TAG: begin
                    if (poly_tag_valid) begin
                        tag       <= poly_tag;
                        tag_valid <= 1'b1;
                        if (!encrypt) auth_fail <= (poly_tag != expected_tag);
                        state <= S_DONE;
                    end
                end

                S_DONE: begin busy <= 1'b0; state <= S_IDLE; end
                default: state <= S_IDLE;
            endcase
        end
    end
endmodule
