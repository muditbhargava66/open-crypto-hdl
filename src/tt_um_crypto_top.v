// ============================================================
//  tt_um_crypto_top.v — TinyTapeout Top Module
//  open-crypto-hdl: ChaCha20-Poly1305 / AES-256-GCM / DES
//
//  TinyTapeout pin interface:
//    ui_in[7:0]   — 8-bit input bus
//    uo_out[7:0]  — 8-bit output bus
//    uio_in[7:0]  — bidirectional in
//    uio_out[7:0] — bidirectional out
//    uio_oe[7:0]  — bidirectional OE (1=drive)
//    ena          — design enabled
//    clk          — 50 MHz typical
//    rst_n        — active-low reset
//
//  SPI Control Protocol (via uio):
//    uio[0] = SCK  (SPI clock)
//    uio[1] = MOSI (SPI data in)
//    uio[2] = MISO (SPI data out)
//    uio[3] = CS_N (chip select, active low)
//
//  SPI Register Map (8-bit addr):
//    0x00 — CIPHER_SEL   [1:0] 00=DES 01=AES-GCM 10=ChaCha20
//    0x01 — CMD          write 0x01=start, 0x02=reset
//    0x02 — STATUS       [0]=busy [1]=done [2]=error
//    0x10..0x17 — KEY    bytes 0-7  (DES: 8 bytes)
//    0x10..0x2F — KEY    bytes 0-31 (AES/ChaCha: 32 bytes)
//    0x30..0x37 — IV/Nonce (DES: unused, AES: 12B, ChaCha: 12B)
//    0x40..0x4F — BLOCK  input data (16 bytes)
//    0x50..0x5F — RESULT output data (16 bytes)
//    0x60..0x6F — TAG    authentication tag (16 bytes)
//
//  SPI frame: [ADDR(8)] [R/W(1)] [DATA(8)]
// ============================================================
`default_nettype none
module tt_um_crypto_top (
    /* verilator lint_off UNUSED */
    input  wire [7:0] ui_in,     // only [3:0] used (result byte index)
    /* verilator lint_on UNUSED */
    output wire [7:0] uo_out,
    /* verilator lint_off UNUSED */
    input  wire [7:0] uio_in,    // only bits [3,1,0] used (CS_N, MOSI, SCK)
    /* verilator lint_on UNUSED */
    output wire [7:0] uio_out,
    output wire [7:0] uio_oe,
    /* verilator lint_off UNUSED */
    input  wire       ena,       // TT-mandated, active-high enable (unused in this design)
    /* verilator lint_on UNUSED */
    input  wire       clk,
    input  wire       rst_n
);
    // ---- SPI signals ----
    wire sck  = uio_in[0];
    wire mosi = uio_in[1];
    wire cs_n = uio_in[3];
    reg  miso;

    assign uio_out = {4'b0000, miso, 3'b000};
    assign uio_oe  = 8'b00000100; // drive bit 2 (MISO)

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

    // Register Read Multiplexer
    reg [7:0] reg_read_data;
    always @(*) begin
        /* verilator lint_off WIDTH */
        casez (spi_addr)
            8'h00: reg_read_data = {6'b000000, cipher_sel};
            8'h02: reg_read_data = status_reg;
            8'h1?: reg_read_data = key_bytes[spi_addr[3:0]];
            8'h2?: reg_read_data = key_bytes[{1'b1, spi_addr[3:0]}];
            8'h3?: reg_read_data = (spi_addr[3:0] < 12) ? iv_bytes[spi_addr[3:0]] : 8'h00;
            8'h4?: reg_read_data = block_bytes[spi_addr[3:0]];
            8'h5?: reg_read_data = result_bytes[spi_addr[3:0]];
            8'h6?: reg_read_data = tag_bytes[spi_addr[3:0]];
            default: reg_read_data = 8'h00;
        endcase
        /* verilator lint_on WIDTH */
    end

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            spi_bit_cnt <= 5'd0;
            spi_done    <= 1'b0;
            sck_prev    <= 1'b0;
            miso        <= 1'b0;
            miso_shift  <= 8'h00;
        end else begin
            sck_prev <= sck;
            spi_done <= 1'b0;

            if (cs_n) begin
                spi_bit_cnt <= 5'd0;
                miso        <= 1'b0;
            end else begin
                if (sck_rise) begin
                    spi_shift <= {spi_shift[22:0], mosi};
                    if (spi_bit_cnt == 5'd16) begin
                        spi_addr <= spi_shift[15:8];
                        spi_rw   <= spi_shift[7];
                        spi_data <= {spi_shift[6:0], mosi};
                        spi_done <= 1'b1;
                        spi_bit_cnt <= 5'd0;
                    end else begin
                        spi_bit_cnt <= spi_bit_cnt + 5'd1;
                    end
                end

                if (sck_fall) begin
                    if (spi_bit_cnt == 5'd9 && spi_rw) begin
                        // Load read data into shift register
                        miso_shift <= reg_read_data;
                    end else if (spi_bit_cnt > 5'd9 && spi_rw) begin
                        miso_shift <= {miso_shift[6:0], 1'b0};
                    end
                end
                
                // Drive MISO with MSB of shift register
                miso <= spi_rw ? miso_shift[7] : 1'b0;
            end
        end
    end

    // ---- Register file ----
    reg [1:0]  cipher_sel;   // 00=DES, 01=AES-GCM, 10=ChaCha20
    reg        cmd_start;
    reg [7:0]  key_bytes  [0:31];
    reg [7:0]  iv_bytes   [0:11];
    reg [7:0]  block_bytes [0:15];
    reg [7:0]  result_bytes [0:15];
    reg [7:0]  tag_bytes [0:15];
    reg [7:0]  status_reg;  // [0]=busy [1]=done

    // ---- Cipher interfaces ----
    wire [63:0]  des_key    = {key_bytes[0],key_bytes[1],key_bytes[2],key_bytes[3],
                               key_bytes[4],key_bytes[5],key_bytes[6],key_bytes[7]};
    wire [63:0]  des_block  = {block_bytes[0],block_bytes[1],block_bytes[2],block_bytes[3],
                               block_bytes[4],block_bytes[5],block_bytes[6],block_bytes[7]};
    wire [63:0]  des_result;
    wire         des_done;
    reg          des_load;
    reg          des_encrypt_r;

    des_core u_des (
        .clk     (clk),
        .rst_n   (rst_n),
        .block   (des_block),
        .key     (des_key),
        .encrypt (des_encrypt_r),
        .load    (des_load),
        .result  (des_result),
        .done    (des_done)
    );

    wire [255:0] aes_key = {
        key_bytes[ 0],key_bytes[ 1],key_bytes[ 2],key_bytes[ 3],
        key_bytes[ 4],key_bytes[ 5],key_bytes[ 6],key_bytes[ 7],
        key_bytes[ 8],key_bytes[ 9],key_bytes[10],key_bytes[11],
        key_bytes[12],key_bytes[13],key_bytes[14],key_bytes[15],
        key_bytes[16],key_bytes[17],key_bytes[18],key_bytes[19],
        key_bytes[20],key_bytes[21],key_bytes[22],key_bytes[23],
        key_bytes[24],key_bytes[25],key_bytes[26],key_bytes[27],
        key_bytes[28],key_bytes[29],key_bytes[30],key_bytes[31]
    };
    wire [127:0] aes_pt = {
        block_bytes[0],block_bytes[1],block_bytes[2],block_bytes[3],
        block_bytes[4],block_bytes[5],block_bytes[6],block_bytes[7],
        block_bytes[8],block_bytes[9],block_bytes[10],block_bytes[11],
        block_bytes[12],block_bytes[13],block_bytes[14],block_bytes[15]
    };
    wire [127:0] aes_ct;
    wire         aes_done;
    reg          aes_load;

    aes_core u_aes (
        .clk       (clk),
        .rst_n     (rst_n),
        .key       (aes_key),
        .plaintext (aes_pt),
        .load      (aes_load),
        .ciphertext(aes_ct),
        .done      (aes_done)
    );

    wire [255:0] chacha_key   = aes_key;
    wire  [95:0] chacha_nonce = {iv_bytes[0],iv_bytes[1],iv_bytes[2],iv_bytes[3],
                                 iv_bytes[4],iv_bytes[5],iv_bytes[6],iv_bytes[7],
                                 iv_bytes[8],iv_bytes[9],iv_bytes[10],iv_bytes[11]};
    /* verilator lint_off UNUSED */
    wire [511:0] chacha_ks;   // only top 128 bits used as output
    /* verilator lint_on UNUSED */
    wire         chacha_done;
    reg          chacha_load;
    reg  [31:0]  chacha_ctr;

    chacha20_core u_chacha (
        .clk      (clk),
        .rst_n    (rst_n),
        .key      (chacha_key),
        .nonce    (chacha_nonce),
        .counter  (chacha_ctr),
        .valid_in (chacha_load),
        .keystream(chacha_ks),
        .valid_out(chacha_done)
    );

    wire [127:0] poly_tag;
    wire         poly_done;
    reg          poly_load;
    reg          poly_init;

    poly1305_core u_poly (
        .clk        (clk),
        .rst_n      (rst_n),
        .key        (aes_key), // reuse aes_key for r||s
        .init       (poly_init),
        .block      (aes_pt),  // reuse aes_pt bus
        .block_len  (5'd16),
        .last_block (1'b1),
        .next       (poly_load),
        .tag        (poly_tag),
        .tag_valid  (poly_done),
        /* verilator lint_off PINCONNECTEMPTY */
        .ready      ()
        /* verilator lint_on PINCONNECTEMPTY */
    );

    // ---- FSM ----
    reg [2:0] fsm;
    localparam FSM_IDLE   = 3'd0;
    localparam FSM_WAIT   = 3'd1;
    localparam FSM_DONE   = 3'd2;

    integer ri;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            cipher_sel   <= 2'd0;
            cmd_start    <= 1'b0;
            des_load     <= 1'b0;
            aes_load     <= 1'b0;
            chacha_load  <= 1'b0;
            poly_load    <= 1'b0;
            poly_init    <= 1'b0;
            des_encrypt_r <= 1'b1;
            status_reg   <= 8'h00;
            fsm          <= FSM_IDLE;
            chacha_ctr   <= 32'd0;
            for (ri = 0; ri < 32; ri = ri + 1) key_bytes[ri]   <= 8'h00;
            for (ri = 0; ri < 12; ri = ri + 1) iv_bytes[ri]    <= 8'h00;
            for (ri = 0; ri < 16; ri = ri + 1) block_bytes[ri] <= 8'h00;
            for (ri = 0; ri < 16; ri = ri + 1) result_bytes[ri] <= 8'h00;
            for (ri = 0; ri < 16; ri = ri + 1) tag_bytes[ri]   <= 8'h00;
        end else begin
            des_load    <= 1'b0;
            aes_load    <= 1'b0;
            chacha_load <= 1'b0;
            poly_load   <= 1'b0;
            poly_init   <= 1'b0;

            // ---- SPI register write ----
            if (spi_done && !spi_rw) begin
                /* verilator lint_off WIDTH */
                casez (spi_addr)
                    8'h00: cipher_sel     <= spi_data[1:0];
                    8'h01: begin
                        if (spi_data == 8'h01) cmd_start <= 1'b1;
                        if (spi_data == 8'h04) poly_init <= 1'b1;
                        if (spi_data == 8'h02) begin
                            fsm        <= FSM_IDLE;
                            status_reg <= 8'h00;
                        end
                    end
                    8'h1?: key_bytes  [spi_addr[3:0]] <= spi_data;
                    8'h2?: key_bytes  [{1'b1,spi_addr[3:0]}] <= spi_data;
                    8'h3?: iv_bytes   [spi_addr[3:0]] <= spi_data;
                    8'h4?: block_bytes[spi_addr[3:0]] <= spi_data;
                    default: ; // ignore unknown addresses
                endcase
                /* verilator lint_on WIDTH */
            end

            // ---- FSM ----
            case (fsm)
                FSM_IDLE: begin
                    if (cmd_start) begin
                        cmd_start  <= 1'b0;
                        status_reg <= 8'h01; // busy
                        case (cipher_sel)
                            2'd0: des_load    <= 1'b1;
                            2'd1: aes_load    <= 1'b1;
                            2'd2: begin
                                chacha_load <= 1'b1;
                                chacha_ctr  <= {block_bytes[0],block_bytes[1],
                                                block_bytes[2],block_bytes[3]};
                            end
                            2'd3: poly_load   <= 1'b1;
                        endcase
                        fsm <= FSM_WAIT;
                    end
                end

                FSM_WAIT: begin
                    case (cipher_sel)
                        2'd0: if (des_done) begin
                            result_bytes[ 0] <= des_result[63:56];
                            result_bytes[ 1] <= des_result[55:48];
                            result_bytes[ 2] <= des_result[47:40];
                            result_bytes[ 3] <= des_result[39:32];
                            result_bytes[ 4] <= des_result[31:24];
                            result_bytes[ 5] <= des_result[23:16];
                            result_bytes[ 6] <= des_result[15: 8];
                            result_bytes[ 7] <= des_result[ 7: 0];
                            fsm <= FSM_DONE;
                        end
                        2'd1: if (aes_done) begin
                            {result_bytes[0],result_bytes[1],result_bytes[2],result_bytes[3],
                             result_bytes[4],result_bytes[5],result_bytes[6],result_bytes[7],
                             result_bytes[8],result_bytes[9],result_bytes[10],result_bytes[11],
                             result_bytes[12],result_bytes[13],result_bytes[14],result_bytes[15]} <= aes_ct;
                            fsm <= FSM_DONE;
                        end
                        2'd2: if (chacha_done) begin
                            {result_bytes[0],result_bytes[1],result_bytes[2],result_bytes[3],
                             result_bytes[4],result_bytes[5],result_bytes[6],result_bytes[7],
                             result_bytes[8],result_bytes[9],result_bytes[10],result_bytes[11],
                             result_bytes[12],result_bytes[13],result_bytes[14],result_bytes[15]}
                                <= chacha_ks[511:384];
                            fsm <= FSM_DONE;
                        end
                        2'd3: if (poly_done) begin
                            {tag_bytes[0],tag_bytes[1],tag_bytes[2],tag_bytes[3],
                             tag_bytes[4],tag_bytes[5],tag_bytes[6],tag_bytes[7],
                             tag_bytes[8],tag_bytes[9],tag_bytes[10],tag_bytes[11],
                             tag_bytes[12],tag_bytes[13],tag_bytes[14],tag_bytes[15]} <= poly_tag;
                            fsm <= FSM_DONE;
                        end
                        default: ;
                    endcase
                end

                FSM_DONE: begin
                    status_reg <= 8'h02; // done
                    fsm        <= FSM_IDLE;
                end
                default: ;
            endcase
        end
    end

    // ---- Output bus ----
    // uo_out reflects the result register addressed by ui_in[3:0]
    assign uo_out = result_bytes[ui_in[3:0]];

endmodule
`default_nettype wire
