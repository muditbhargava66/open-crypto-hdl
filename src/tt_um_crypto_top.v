// ============================================================
//  tt_um_crypto_top.v — TinyTapeout Top Module (v1.1.0 Silicon Ready)
//  open-crypto-hdl: AEAD Suite with Unified Core Sharing
// ============================================================
`default_nettype none
module tt_um_crypto_top (
    input  wire [7:0] ui_in,
    output wire [7:0] uo_out,
    input  wire [7:0] uio_in,
    output wire [7:0] uio_out,
    output wire [7:0] uio_oe,
    /* verilator lint_off UNUSED */
    input  wire       ena,
    /* verilator lint_on UNUSED */
    input  wire       clk,
    input  wire       rst_n
);
    // ---- CDC Synchronizers ----
    reg [1:0] sck_sync, mosi_sync, csn_sync;
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            sck_sync  <= 2'b0; mosi_sync <= 2'b0; csn_sync  <= 2'b11;
        end else begin
            sck_sync  <= {sck_sync[0],  uio_in[0]};
            mosi_sync <= {mosi_sync[0], uio_in[1]};
            csn_sync  <= {csn_sync[0],  uio_in[3]};
        end
    end

    wire sck  = sck_sync[1];
    wire mosi = mosi_sync[1];
    wire cs_n = csn_sync[1];
    reg  miso;

    assign uio_out = {4'b0000, miso, 3'b000};
    assign uio_oe  = 8'b00000100;

    // ---- SPI deserializer ----
    reg  [7:0]  spi_addr;
    reg  [7:0]  spi_data;
    reg         spi_rw;
    reg  [4:0]  spi_bit_cnt;
    /* verilator lint_off UNUSED */
    reg  [23:0] spi_shift;
    /* verilator lint_on UNUSED */
    reg  [7:0]  miso_shift;
    reg         spi_done;
    reg         sck_prev;

    wire sck_rise = sck && !sck_prev;
    wire sck_fall = !sck && sck_prev;

    reg [7:0] reg_read_data;
    always @(*) begin
        casez (spi_addr)
            8'h00: reg_read_data = {4'b0, cipher_sel};
            8'h02: reg_read_data = status_reg;
            8'h04, 8'h05, 8'h06, 8'h07: reg_read_data = aad_len_bytes[spi_addr[1:0]];
            8'h08, 8'h09, 8'h0a, 8'h0b: reg_read_data = pt_len_bytes[spi_addr[1:0]];
            8'h1?, 8'h2?: reg_read_data = key_bytes[spi_addr[4:0]];
            8'h3?: reg_read_data = (spi_addr[3:0] < 12) ? iv_bytes[spi_addr[3:0]] : 8'h00;
            8'h4?: reg_read_data = block_bytes[spi_addr[3:0]];
            8'h5?: reg_read_data = result_bytes[spi_addr[3:0]];
            8'h6?: reg_read_data = tag_bytes[spi_addr[3:0]];
            default: reg_read_data = 8'h00;
        endcase
    end

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            spi_bit_cnt <= 5'd0; spi_done <= 1'b0; sck_prev <= 1'b0; miso <= 1'b0; miso_shift <= 8'h00;
        end else begin
            sck_prev <= sck; spi_done <= 1'b0;
            if (cs_n) begin
                spi_bit_cnt <= 5'd0; miso <= 1'b0;
            end else begin
                if (sck_rise) begin
                    spi_shift <= {spi_shift[22:0], mosi};
                    if (spi_bit_cnt == 5'd16) begin
                        spi_addr <= spi_shift[15:8]; spi_rw <= spi_shift[7]; spi_data <= {spi_shift[6:0], mosi};
                        spi_done <= 1'b1; spi_bit_cnt <= 5'd0;
                    end else spi_bit_cnt <= spi_bit_cnt + 5'd1;
                end
                if (sck_fall) begin
                    if (spi_bit_cnt == 5'd9 && spi_rw) miso_shift <= reg_read_data;
                    else if (spi_bit_cnt > 5'd9 && spi_rw) miso_shift <= {miso_shift[6:0], 1'b0};
                end
                miso <= spi_rw ? miso_shift[7] : 1'b0;
            end
        end
    end

    // ---- Register file ----
    reg [3:0]  cipher_sel;
    reg        cmd_start;
    reg        cmd_aead_next;
    reg [7:0]  aad_len_bytes [0:3];
    reg [7:0]  pt_len_bytes  [0:3];
    reg [7:0]  key_bytes     [0:31];
    reg [7:0]  iv_bytes      [0:11];
    reg [7:0]  block_bytes   [0:15];
    reg [7:0]  result_bytes  [0:15];
    reg [7:0]  tag_bytes     [0:15];
    reg [7:0]  status_reg;

    wire [31:0] aad_len_w = {aad_len_bytes[0], aad_len_bytes[1], aad_len_bytes[2], aad_len_bytes[3]};
    wire [31:0] pt_len_w  = {pt_len_bytes[0],  pt_len_bytes[1],  pt_len_bytes[2],  pt_len_bytes[3]};

    wire [255:0] full_key = {key_bytes[0],key_bytes[1],key_bytes[2],key_bytes[3],key_bytes[4],key_bytes[5],key_bytes[6],key_bytes[7],
                             key_bytes[8],key_bytes[9],key_bytes[10],key_bytes[11],key_bytes[12],key_bytes[13],key_bytes[14],key_bytes[15],
                             key_bytes[16],key_bytes[17],key_bytes[18],key_bytes[19],key_bytes[20],key_bytes[21],key_bytes[22],key_bytes[23],
                             key_bytes[24],key_bytes[25],key_bytes[26],key_bytes[27],key_bytes[28],key_bytes[29],key_bytes[30],key_bytes[31]};
    wire [127:0] block_128 = {block_bytes[0],block_bytes[1],block_bytes[2],block_bytes[3],block_bytes[4],block_bytes[5],block_bytes[6],block_bytes[7],
                              block_bytes[8],block_bytes[9],block_bytes[10],block_bytes[11],block_bytes[12],block_bytes[13],block_bytes[14],block_bytes[15]};
    wire [95:0]  iv_96     = {iv_bytes[0],iv_bytes[1],iv_bytes[2],iv_bytes[3],iv_bytes[4],iv_bytes[5],iv_bytes[6],iv_bytes[7],iv_bytes[8],iv_bytes[9],iv_bytes[10],iv_bytes[11]};

    // ---- Shared Core MUXing ----
    reg  [127:0] aes_mux_pt;
    reg          aes_mux_load;
    wire [127:0] aes_core_ct;
    wire         aes_core_done;
    aes_core u_aes (.clk(clk), .rst_n(rst_n), .key(full_key), .plaintext(aes_mux_pt), .load(aes_mux_load), .ciphertext(aes_core_ct), .done(aes_core_done));

    reg  [31:0]  chacha_mux_ctr;
    reg          chacha_mux_load;
    wire [511:0] chacha_core_ks;
    wire         chacha_core_done;
    chacha20_core u_chacha (.clk(clk), .rst_n(rst_n), .key(full_key), .nonce(iv_96), .counter(chacha_mux_ctr), .valid_in(chacha_mux_load), .keystream(chacha_core_ks), .valid_out(chacha_core_done));

    reg  [255:0] poly_mux_key;
    reg  [127:0] poly_mux_block;
    reg  [4:0]   poly_mux_len;
    reg          poly_mux_init, poly_mux_next, poly_mux_last;
    wire [127:0] poly_core_tag;
    wire         poly_core_done;
    poly1305_core u_poly (.clk(clk), .rst_n(rst_n), .key(poly_mux_key), .init(poly_mux_init), .block(poly_mux_block), .block_len(poly_mux_len), .last_block(poly_mux_last), .next(poly_mux_next), .tag(poly_core_tag), .tag_valid(poly_core_done), .ready());

    reg          des_load, des_encrypt_r;
    wire [63:0]  des_result;
    wire         des_done;
    des_core u_des (.clk(clk), .rst_n(rst_n), .block(block_128[127:64]), .key(full_key[255:192]), .encrypt(des_encrypt_r), .load(des_load), .result(des_result), .done(des_done));

    // ---- AEAD Logic Wrappers ----
    wire [127:0] gcm_aes_pt, gcm_ct, gcm_tag;
    wire         gcm_aes_load, gcm_ct_valid, gcm_tag_valid;
    reg          gcm_start, gcm_aad_valid, gcm_pt_valid;
    aes_gcm_top u_aes_gcm (.clk(clk), .rst_n(rst_n), .key(full_key), .iv(iv_96), .aad_len({32'd0, aad_len_w}), .pt_len({32'd0, pt_len_w}), .start(gcm_start),
                           .aad_block(block_128), .aad_valid(gcm_aad_valid), .aad_ready(), .pt_block(block_128), .pt_valid(gcm_pt_valid),
                           .ct_block(gcm_ct), .ct_valid(gcm_ct_valid), .tag(gcm_tag), .tag_valid(gcm_tag_valid), .busy(),
                           .aes_pt(gcm_aes_pt), .aes_load(gcm_aes_load), .aes_ct(aes_core_ct), .aes_done(aes_core_done));

    wire [31:0]  cp_chacha_ctr;
    wire         cp_chacha_start, cp_poly_init, cp_poly_next, cp_poly_last, cp_out_valid, cp_tag_valid;
    wire [255:0] cp_otk;
    wire [127:0] cp_poly_block, cp_block, cp_tag;
    wire [4:0]   cp_poly_len;
    reg          cp_start, cp_aad_valid, cp_data_valid, cp_aad_last, cp_data_last;
    chacha20poly1305_top u_chacha_poly (.clk(clk), .rst_n(rst_n), .key(full_key), .nonce(iv_96), .start(cp_start), .encrypt(cipher_sel[3]),
                                        .aad_block(block_128), .aad_len(5'd16), .aad_valid(cp_aad_valid), .aad_last(cp_aad_last),
                                        .data_block(block_128), .data_len(5'd16), .data_valid(cp_data_valid), .data_last(cp_data_last),
                                        .out_block(cp_block), .out_len(), .out_valid(cp_out_valid), .out_last(), .tag(cp_tag), .tag_valid(cp_tag_valid), .busy(), .auth_fail(),
                                        .chacha_ctr(cp_chacha_ctr), .chacha_start(cp_chacha_start), .chacha_ks(chacha_core_ks), .chacha_done(chacha_core_done),
                                        .cp_otk(cp_otk), .poly_block(cp_poly_block), .poly_block_len(cp_poly_len), .poly_init(cp_poly_init), .poly_next(cp_poly_next), .poly_last(cp_poly_last), .poly_tag(poly_core_tag), .poly_tag_valid(poly_core_done));

    // ---- MUX Implementation ----
    always @(*) begin
        // AES MUX
        if (cipher_sel[2:0] == 1) begin aes_mux_pt = block_128; aes_mux_load = (fsm == S_IDLE && cmd_start); end
        else if (cipher_sel[2:0] == 4) begin aes_mux_pt = gcm_aes_pt; aes_mux_load = gcm_aes_load; end
        else begin aes_mux_pt = 128'd0; aes_mux_load = 1'b0; end
        // ChaCha MUX
        if (cipher_sel[2:0] == 2) begin chacha_mux_ctr = block_128[127:96]; chacha_mux_load = (fsm == S_IDLE && cmd_start); end
        else if (cipher_sel[2:0] == 5) begin chacha_mux_ctr = cp_chacha_ctr; chacha_mux_load = cp_chacha_start; end
        else begin chacha_mux_ctr = 32'd0; chacha_mux_load = 1'b0; end
        // Poly MUX
        if (cipher_sel[2:0] == 3) begin
            poly_mux_key = full_key; poly_mux_block = block_128; poly_mux_len = 5'd16; poly_mux_last = 1'b1;
            poly_mux_init = (spi_done && !spi_rw && spi_addr == 8'h01 && spi_data == 8'h04);
            poly_mux_next = (fsm == S_IDLE && cmd_start);
        end else if (cipher_sel[2:0] == 5) begin
            poly_mux_key = cp_otk; poly_mux_block = cp_poly_block; poly_mux_len = cp_poly_len; poly_mux_init = cp_poly_init; poly_mux_next = cp_poly_next; poly_mux_last = cp_poly_last;
        end else begin
            poly_mux_key = 256'd0; poly_mux_block = 128'd0; poly_mux_len = 5'd0; poly_mux_init = 1'b0; poly_mux_next = 1'b0; poly_mux_last = 1'b0;
        end
    end

    // ---- Main FSM ----
    reg [3:0] fsm;
    localparam S_IDLE      = 4'd0;
    localparam S_WAIT_RAW  = 4'd1;
    localparam S_AEAD_STRM = 4'd2;
    localparam S_DONE      = 4'd3;

    integer ri;
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            fsm <= S_IDLE; status_reg <= 8'h00; cipher_sel <= 4'd0; cmd_start <= 1'b0; cmd_aead_next <= 1'b0;
            des_load <= 1'b0; des_encrypt_r <= 1'b1; gcm_start <= 1'b0; gcm_aad_valid <= 1'b0; gcm_pt_valid <= 1'b0;
            cp_start <= 1'b0; cp_aad_valid <= 1'b0; cp_data_valid <= 1'b0; cp_aad_last <= 1'b0; cp_data_last <= 1'b0;
            for (ri=0; ri<32; ri=ri+1) key_bytes[ri] <= 8'h0;
            for (ri=0; ri<12; ri=ri+1) iv_bytes[ri]  <= 8'h0;
            for (ri=0; ri<16; ri=ri+1) block_bytes[ri] <= 8'h0;
            for (ri=0; ri<16; ri=ri+1) result_bytes[ri] <= 8'h0;
            for (ri=0; ri<16; ri=ri+1) tag_bytes[ri] <= 8'h0;
            for (ri=0; ri<4; ri=ri+1) begin aad_len_bytes[ri] <= 8'h0; pt_len_bytes[ri] <= 8'h0; end
        end else begin
            des_load <= 1'b0; gcm_start <= 1'b0; gcm_aad_valid <= 1'b0; gcm_pt_valid <= 1'b0; cp_start <= 1'b0; cp_aad_valid <= 1'b0; cp_data_valid <= 1'b0;
            if (spi_done && !spi_rw) begin
                casez (spi_addr)
                    8'h00: begin cipher_sel <= spi_data[3:0]; des_encrypt_r <= spi_data[3]; end
                    8'h01: begin
                        if (spi_data == 8'h01) cmd_start <= 1'b1;
                        if (spi_data == 8'h02) begin fsm <= S_IDLE; status_reg <= 8'h0; end
                        if (spi_data == 8'h08) cmd_aead_next <= 1'b1;
                    end
                    8'h04, 8'h05, 8'h06, 8'h07: aad_len_bytes[spi_addr[1:0]] <= spi_data;
                    8'h08, 8'h09, 8'h0a, 8'h0b: pt_len_bytes[spi_addr[1:0]]  <= spi_data;
                    8'h1?, 8'h2?: key_bytes[spi_addr[4:0]] <= spi_data;
                    8'h3?: if (spi_addr[3:0] < 12) iv_bytes[spi_addr[3:0]] <= spi_data;
                    8'h4?: block_bytes[spi_addr[3:0]] <= spi_data;
                    default: ;
                endcase
            end
            case (fsm)
                S_IDLE: if (cmd_start) begin
                    cmd_start <= 1'b0; status_reg <= 8'h01;
                    if (cipher_sel[2:0] < 4) begin
                        if (cipher_sel[2:0] == 0) des_load <= 1'b1;
                        fsm <= S_WAIT_RAW;
                    end else begin
                        if (cipher_sel[2:0] == 4) gcm_start <= 1'b1;
                        else begin cp_start <= 1'b1; cp_aad_last <= (aad_len_w == 0); cp_data_last <= (pt_len_w <= 16); end
                        fsm <= S_AEAD_STRM;
                    end
                end
                S_WAIT_RAW: if (des_done || aes_core_done || chacha_core_done || poly_core_done) begin
                    if (des_done) {result_bytes[0],result_bytes[1],result_bytes[2],result_bytes[3],result_bytes[4],result_bytes[5],result_bytes[6],result_bytes[7]} <= des_result;
                    if (aes_core_done) {result_bytes[0],result_bytes[1],result_bytes[2],result_bytes[3],result_bytes[4],result_bytes[5],result_bytes[6],result_bytes[7],result_bytes[8],result_bytes[9],result_bytes[10],result_bytes[11],result_bytes[12],result_bytes[13],result_bytes[14],result_bytes[15]} <= aes_core_ct;
                    if (chacha_core_done) {result_bytes[0],result_bytes[1],result_bytes[2],result_bytes[3],result_bytes[4],result_bytes[5],result_bytes[6],result_bytes[7],result_bytes[8],result_bytes[9],result_bytes[10],result_bytes[11],result_bytes[12],result_bytes[13],result_bytes[14],result_bytes[15]} <= chacha_core_ks[511:384];
                    if (poly_core_done) {tag_bytes[0],tag_bytes[1],tag_bytes[2],tag_bytes[3],tag_bytes[4],tag_bytes[5],tag_bytes[6],tag_bytes[7],tag_bytes[8],tag_bytes[9],tag_bytes[10],tag_bytes[11],tag_bytes[12],tag_bytes[13],tag_bytes[14],tag_bytes[15]} <= poly_core_tag;
                    fsm <= S_DONE;
                end
                S_AEAD_STRM: begin
                    if (cmd_aead_next) begin
                        cmd_aead_next <= 1'b0;
                        if (cipher_sel[2:0] == 4) begin if (aad_len_w > 0) gcm_aad_valid <= 1'b1; else gcm_pt_valid <= 1'b1; end
                        else begin if (aad_len_w > 0) cp_aad_valid <= 1'b1; else cp_data_valid <= 1'b1; end
                    end
                    if (gcm_ct_valid || cp_out_valid) begin
                        {result_bytes[0],result_bytes[1],result_bytes[2],result_bytes[3],result_bytes[4],result_bytes[5],result_bytes[6],result_bytes[7],result_bytes[8],result_bytes[9],result_bytes[10],result_bytes[11],result_bytes[12],result_bytes[13],result_bytes[14],result_bytes[15]} <= (cipher_sel[2:0]==4) ? gcm_ct : cp_block;
                        status_reg <= 8'h02;
                    end
                    if (gcm_tag_valid || cp_tag_valid) begin
                        {tag_bytes[0],tag_bytes[1],tag_bytes[2],tag_bytes[3],tag_bytes[4],tag_bytes[5],tag_bytes[6],tag_bytes[7],tag_bytes[8],tag_bytes[9],tag_bytes[10],tag_bytes[11],tag_bytes[12],tag_bytes[13],tag_bytes[14],tag_bytes[15]} <= (cipher_sel[2:0]==4) ? gcm_tag : cp_tag;
                        fsm <= S_DONE;
                    end
                end
                S_DONE: begin status_reg <= 8'h02; fsm <= S_IDLE; end
                default: fsm <= S_IDLE;
            endcase
        end
    end
    assign uo_out = result_bytes[ui_in[3:0]];
endmodule
