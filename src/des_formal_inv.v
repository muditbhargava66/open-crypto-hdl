// ============================================================
//  des_formal_inv.v — DES Encrypt/Decrypt Inverse Property
// ============================================================
`default_nettype none
module des_formal_inv (
    input  wire         clk,
    input  wire         rst_n,
    input  wire [63:0]  key,
    input  wire [63:0]  plaintext,
    input  wire         load
);
    wire [63:0] ct;
    wire        ct_done;
    wire [63:0] pt_recovered;
    wire        pt_done;

    // Encryptor
    des_core u_enc (
        .clk(clk),
        .rst_n(rst_n),
        .key(key),
        .block(plaintext),
        .encrypt(1'b1),
        .load(load),
        .result(ct),
        .done(ct_done)
    );

    // Decryptor
    des_core u_dec (
        .clk(clk),
        .rst_n(rst_n),
        .key(key),
        .block(ct),
        .encrypt(1'b0),
        .load(ct_done),
        .result(pt_recovered),
        .done(pt_done)
    );

`ifdef FORMAL
    reg f_past_valid = 1'b0;
    always @(posedge clk) f_past_valid <= 1'b1;

    always @(posedge clk) begin
        if (!f_past_valid) assume(!rst_n);
        else assume(rst_n);
    end

    // Property: recovered plaintext must match original
    always @(posedge clk) begin
        if (rst_n && pt_done) begin
            assert(pt_recovered == $past(plaintext, 40)); // DES takes ~18+18+wait cycles
        end
    end

    // Use symbolic constant for plaintext to ensure it's stable
    always @(posedge clk) begin
        if (f_past_valid) assume(plaintext == $past(plaintext));
        if (f_past_valid) assume(key == $past(key));
    end
`endif
endmodule
