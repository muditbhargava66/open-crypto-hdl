// ============================================================
//  aes_ctr.v — AES-256 Counter Mode (CTR)
//  NIST SP 800-38A §6.5
//
//  CTR mode: C[i] = P[i] XOR AES_K(T[i])
//  where T[i] = nonce || counter_i  (96 || 32 bits = 128-bit block)
//
//  Streaming interface — one 128-bit block per operation:
//    1. Assert start with key[255:0], nonce[95:0], initial_ctr[31:0]
//    2. For each plaintext block: set data_in, assert data_valid
//    3. Collect data_out when data_out_valid pulses
//    4. Counter auto-increments after each block
//
//  Latency: 16 cycles per block (AES-256 latency)
//  Can pipeline: next block starts as soon as AES completes
// ============================================================
`default_nettype none
module aes_ctr (
    input  wire         clk,
    input  wire         rst_n,

    // Configuration
    input  wire [255:0] key,
    input  wire  [95:0] nonce,
    input  wire  [31:0] initial_ctr,
    input  wire         start,         // pulse to load key/nonce/ctr

    // Data interface
    input  wire [127:0] data_in,       // plaintext or ciphertext
    input  wire         data_valid,
    output reg  [127:0] data_out,      // ciphertext or plaintext
    output reg          data_out_valid,

    // Status
    output reg          busy,
    output reg  [31:0]  ctr_out        // current counter value
);
    // ---- Registered configuration ----
    reg [255:0] key_r;
    reg  [95:0] nonce_r;
    reg  [31:0] ctr_r;

    // ---- AES core interface ----
    reg  [127:0] aes_pt;
    reg          aes_load;
    wire [127:0] aes_ct;
    wire         aes_done;

    aes_core u_aes (
        .clk       (clk),
        .rst_n     (rst_n),
        .key       (key_r),
        .plaintext (aes_pt),
        .load      (aes_load),
        .ciphertext(aes_ct),
        .done      (aes_done)
    );

    // ---- Pending data register ----
    reg [127:0] data_pending;
    reg         data_pending_valid;

    // ---- FSM ----
    localparam S_IDLE    = 2'd0;
    localparam S_ENCRYPT = 2'd1;  // AES encrypting counter block
    localparam S_XOR     = 2'd2;  // XOR with pending data
    localparam S_PRELOAD = 2'd3;  // pre-fetch next counter block

    reg [1:0] state;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state             <= S_IDLE;
            busy              <= 1'b0;
            data_out_valid    <= 1'b0;
            aes_load          <= 1'b0;
            data_pending_valid <= 1'b0;
            ctr_out           <= 32'd0;
        end else begin
            aes_load       <= 1'b0;
            data_out_valid <= 1'b0;

            if (start) begin
                key_r     <= key;
                nonce_r   <= nonce;
                ctr_r     <= initial_ctr;
                ctr_out   <= initial_ctr;
                state     <= S_IDLE;
                busy      <= 1'b0;
                data_pending_valid <= 1'b0;
            end

            case (state)
                S_IDLE: begin
                    // Wait for incoming data
                    if (data_valid) begin
                        // Latch data and kick AES on current counter
                        data_pending       <= data_in;
                        data_pending_valid <= 1'b1;
                        // Encrypt nonce || ctr
                        aes_pt   <= {nonce_r, ctr_r};
                        aes_load <= 1'b1;
                        busy     <= 1'b1;
                        state    <= S_ENCRYPT;
                    end
                end

                S_ENCRYPT: begin
                    // Accept more incoming data while AES is running (pipeline)
                    if (data_valid && !data_pending_valid) begin
                        data_pending       <= data_in;
                        data_pending_valid <= 1'b1;
                    end

                    if (aes_done) begin
                        if (data_pending_valid) begin
                            // XOR keystream with pending data
                            data_out       <= data_pending ^ aes_ct;
                            data_out_valid <= 1'b1;
                            data_pending_valid <= 1'b0;
                            ctr_r   <= ctr_r + 32'd1;
                            ctr_out <= ctr_r + 32'd1;

                            // Check if more data is queued or incoming
                            if (data_valid) begin
                                // Another block ready — pipeline immediately
                                data_pending       <= data_in;
                                data_pending_valid <= 1'b1;
                                aes_pt   <= {nonce_r, ctr_r + 32'd1};
                                aes_load <= 1'b1;
                                state    <= S_ENCRYPT;
                            end else begin
                                // Pre-encrypt next counter block speculatively
                                aes_pt   <= {nonce_r, ctr_r + 32'd1};
                                aes_load <= 1'b1;
                                state    <= S_PRELOAD;
                            end
                        end else begin
                            // No data yet — hold keystream and wait
                            state <= S_XOR;
                        end
                    end
                end

                S_XOR: begin
                    // Keystream computed, waiting for data
                    if (data_valid) begin
                        data_out       <= data_in ^ aes_ct;
                        data_out_valid <= 1'b1;
                        ctr_r   <= ctr_r + 32'd1;
                        ctr_out <= ctr_r + 32'd1;
                        // Pre-load next keystream speculatively
                        aes_pt   <= {nonce_r, ctr_r + 32'd1};
                        aes_load <= 1'b1;
                        state    <= S_PRELOAD;
                    end
                end

                S_PRELOAD: begin
                    // Speculative pre-encryption of next counter block
                    if (data_valid) begin
                        data_pending       <= data_in;
                        data_pending_valid <= 1'b1;
                    end
                    if (aes_done) begin
                        if (data_pending_valid) begin
                            data_out       <= data_pending ^ aes_ct;
                            data_out_valid <= 1'b1;
                            data_pending_valid <= 1'b0;
                            ctr_r   <= ctr_r + 32'd1;
                            ctr_out <= ctr_r + 32'd1;
                            aes_pt   <= {nonce_r, ctr_r + 32'd1};
                            aes_load <= 1'b1;
                            state    <= S_PRELOAD;
                        end else begin
                            // Return to XOR state — hold keystream
                            state <= S_XOR;
                        end
                    end
                    if (!data_valid && !data_pending_valid && !aes_load) begin
                        busy  <= 1'b0;
                        state <= S_IDLE;
                    end
                end
            endcase
        end
    end
endmodule
`default_nettype wire
