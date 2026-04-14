// ============================================================
//  tdes_core.v — Triple-DES (3DES) Wrapper
//  NIST SP 800-67 Rev. 2 / ANSI X9.52
//
//  Implements:
//    EDE mode (key1 ≠ key2 ≠ key3): E(key1) → D(key2) → E(key3)
//    EEE mode (all three keys used for encrypt): E(k1)→E(k2)→E(k3)
//    2TDEA:  key1 = key3 (keying option 2)
//
//  Key: 192-bit (key1[63:0] || key2[127:64] || key3[191:128])
//  Block: 64-bit
//  Latency: 3 × 18 = 54 cycles (3 sequential DES operations)
//
//  Port `mode` selects:
//    2'b00 = 3TDEA EDE encrypt
//    2'b01 = 3TDEA EDE decrypt
//    2'b10 = 2TDEA EDE encrypt (key3 = key1 internally)
//    2'b11 = 2TDEA EDE decrypt
//
//  NOTE: DES/3DES is cryptographically deprecated. This
//  implementation exists for legacy protocol compatibility only.
// ============================================================
`default_nettype none
module tdes_core (
    input  wire         clk,
    input  wire         rst_n,
    input  wire [63:0]  block,
    input  wire [191:0] key,        // key1 || key2 || key3 (MSB first)
    input  wire [1:0]   mode,       // see header
    input  wire         load,
    output reg  [63:0]  result,
    output reg          done
);
    // ---- Key extraction ----
    wire [63:0] key1 = key[191:128];
    wire [63:0] key2 = key[127: 64];
    wire [63:0] key3 = (mode[1]) ? key[191:128] : key[63:0];  // 2TDEA: k3=k1

    // ---- DES instance signals ----
    reg  [63:0]  des_block;
    reg  [63:0]  des_key;
    reg          des_encrypt;
    reg          des_load;
    wire [63:0]  des_result;
    wire         des_done;

    des_core u_des (
        .clk     (clk),
        .rst_n   (rst_n),
        .block   (des_block),
        .key     (des_key),
        .encrypt (des_encrypt),
        .load    (des_load),
        .result  (des_result),
        .done    (des_done)
    );

    // ---- 3DES FSM ----
    // States: 0=idle, 1=op1_start, 2=op1_wait, 3=op2_start, 4=op2_wait,
    //         5=op3_start, 6=op3_wait, 7=output
    reg [2:0] state;
    reg [1:0] mode_r;

    localparam S_IDLE      = 3'd0;
    localparam S_OP1_START = 3'd1;
    localparam S_OP1_WAIT  = 3'd2;
    localparam S_OP2_START = 3'd3;
    localparam S_OP2_WAIT  = 3'd4;
    localparam S_OP3_START = 3'd5;
    localparam S_OP3_WAIT  = 3'd6;
    localparam S_DONE      = 3'd7;

    reg [63:0] inter1, inter2;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state    <= S_IDLE;
            des_load <= 1'b0;
            done     <= 1'b0;
        end else begin
            des_load <= 1'b0;
            done     <= 1'b0;

            case (state)
                S_IDLE: begin
                    if (load) begin
                        mode_r <= mode;
                        state  <= S_OP1_START;
                    end
                end

                // ── Operation 1 ─────────────────────────────────────────
                S_OP1_START: begin
                    // Encrypt: E(key1, block)   Decrypt: D(key3, block)
                    des_block   <= block;
                    des_key     <= mode_r[0] ? key3 : key1;
                    des_encrypt <= ~mode_r[0]; // encrypt for mode=ENC, decrypt for DEC
                    des_load    <= 1'b1;
                    state       <= S_OP1_WAIT;
                end
                S_OP1_WAIT: begin
                    if (des_done) begin
                        inter1 <= des_result;
                        state  <= S_OP2_START;
                    end
                end

                // ── Operation 2 ─────────────────────────────────────────
                S_OP2_START: begin
                    // Encrypt: D(key2, inter1)  Decrypt: E(key2, inter1)
                    des_block   <= inter1;
                    des_key     <= key2;
                    des_encrypt <= mode_r[0]; // flipped vs op1
                    des_load    <= 1'b1;
                    state       <= S_OP2_WAIT;
                end
                S_OP2_WAIT: begin
                    if (des_done) begin
                        inter2 <= des_result;
                        state  <= S_OP3_START;
                    end
                end

                // ── Operation 3 ─────────────────────────────────────────
                S_OP3_START: begin
                    // Encrypt: E(key3, inter2)  Decrypt: D(key1, inter2)
                    des_block   <= inter2;
                    des_key     <= mode_r[0] ? key1 : key3;
                    des_encrypt <= ~mode_r[0];
                    des_load    <= 1'b1;
                    state       <= S_OP3_WAIT;
                end
                S_OP3_WAIT: begin
                    if (des_done) begin
                        result <= des_result;
                        state  <= S_DONE;
                    end
                end

                S_DONE: begin
                    done  <= 1'b1;
                    state <= S_IDLE;
                end
            endcase
        end
    end
endmodule
`default_nettype wire
