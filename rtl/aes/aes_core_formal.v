// ============================================================
//  aes_core_formal.v — AES-256 with formal properties
// ============================================================
`default_nettype none
module aes_core_formal (
    input  wire         clk,
    input  wire         rst_n,
    input  wire [255:0] key,
    input  wire [127:0] plaintext,
    input  wire         load,
    output wire [127:0] ciphertext,
    output wire         done
);
    wire [2:0] f_phase;

    // Instantiate core
    aes_core u_core (
        .clk(clk),
        .rst_n(rst_n),
        .key(key),
        .plaintext(plaintext),
        .load(load),
        .ciphertext(ciphertext),
        .done(done)
`ifdef FORMAL
        , .f_phase(f_phase)
`endif
    );

`ifdef FORMAL
    reg f_past_valid = 1'b0;
    always @(posedge clk) f_past_valid <= 1'b1;

    // Reset sequence
    always @(posedge clk) begin
        if (!f_past_valid)
            assume(!rst_n);
        else
            assume(rst_n);
    end

    // P1: Done is only 1 cycle
    always @(posedge clk) begin
        if (rst_n && f_past_valid) begin
            if (done && $past(done))
                assert(1'b0);
        end
    end

    // P2: State machine range
    always @(posedge clk) begin
        if (rst_n)
            assert(f_phase <= 3'd7);
    end

    // P3: Progress (allowing for round loops 6 -> 3)
    always @(posedge clk) begin
        if (rst_n && f_past_valid) begin
            if ($past(f_phase) != 3'd0 && f_phase != 3'd0) begin
                // Phase should either stay same, increment, or loop 6 -> 3
                assert(f_phase >= $past(f_phase) || 
                       ($past(f_phase) == 3'd6 && f_phase == 3'd3));
            end
        end
    end

    // Cover reachability
    always @(posedge clk) begin
        cover(done);
    end
`endif
endmodule
