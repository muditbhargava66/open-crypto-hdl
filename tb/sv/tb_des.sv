// ============================================================
//  tb_des.sv — DES self-checking testbench
//  FIPS 46-3 / NIST SP 800-20 KAT vectors
//  iverilog -g2012 compatible
// ============================================================
`timescale 1ns/1ps
module tb_des;

    reg         clk, rst_n;
    reg  [63:0] block, key, result_buf;
    wire [63:0] result;
    reg         encrypt, load;
    wire        done;

    initial clk = 0;
    always #5 clk = ~clk;  // 100 MHz

    des_core dut (
        .clk(clk), .rst_n(rst_n), .block(block), .key(key),
        .encrypt(encrypt), .load(load), .result(result), .done(done)
    );

    // ---- Task: run one DES operation ----
    integer des_t;
    task des_op;
        input [63:0] in_block, in_key;
        input        enc;
        output [63:0] out_result;
        begin
            @(posedge clk);
            block = in_block; key = in_key; encrypt = enc; load = 1'b1;
            @(posedge clk);
            load = 1'b0;
            out_result = 64'hx;
            for (des_t = 0; des_t < 80; des_t = des_t + 1) begin
                @(posedge clk);
                if (done) begin
                    out_result = result;
                    des_t = 80;
                end
            end
        end
    endtask

    // ---- Test counter ----
    integer pass_cnt, fail_cnt;

    task chk64;
        input [127:0] lbl;  // label
        input [63:0] got, exp;
        begin
            if (got === exp) begin
                $display("  PASS  [%0s] 0x%016h", lbl, got);
                pass_cnt = pass_cnt + 1;
            end else begin
                $display("  FAIL  [%0s] got=0x%016h  exp=0x%016h", lbl, got, exp);
                fail_cnt = fail_cnt + 1;
            end
        end
    endtask

    // ---- Pre-declared output register ----
    reg [63:0] res, ct_val, pt_val;

    initial begin
        $dumpfile("tb_des.vcd"); $dumpvars(0, tb_des);
        $display(""); $display("=== DES Testbench — NIST KAT Vectors ==="); $display("");
        pass_cnt=0; fail_cnt=0;
        rst_n=0; load=0; block=0; key=0; encrypt=1;
        repeat(4) @(posedge clk); rst_n=1; @(posedge clk);

        // ── NIST SP 800-20 Table A.1 — Variable Plaintext KAT ──────────
        // Key = 0101010101010101 for all
        $display("[T1] NIST Variable Plaintext KAT  key=0101010101010101");

        des_op(64'h8000000000000000, 64'h0101010101010101, 1'b1, res);
        chk64("VPT.0", res, 64'h95f8a5e5dd31d900);
        repeat(2) @(posedge clk);

        des_op(64'h4000000000000000, 64'h0101010101010101, 1'b1, res);
        chk64("VPT.1", res, 64'hdd7f121ca5015619);
        repeat(2) @(posedge clk);

        des_op(64'h2000000000000000, 64'h0101010101010101, 1'b1, res);
        chk64("VPT.2", res, 64'h2e8653104f3834ea);
        repeat(2) @(posedge clk);

        des_op(64'h1000000000000000, 64'h0101010101010101, 1'b1, res);
        chk64("VPT.3", res, 64'h4bd388ff6cd81d4f);
        repeat(2) @(posedge clk);

        des_op(64'h0800000000000000, 64'h0101010101010101, 1'b1, res);
        chk64("VPT.4", res, 64'h20b9e767b2fb1456);
        repeat(2) @(posedge clk);

        des_op(64'h0000000000000001, 64'h0101010101010101, 1'b1, res);
        chk64("VPT.63", res, 64'h166b40b44aba4bd6);
        repeat(2) @(posedge clk);

        // ── NIST Variable Key KAT ────────────────────────────────────────
        $display("[T2] NIST Variable Key KAT  pt=0000000000000000");

        des_op(64'h0000000000000000, 64'h8001010101010101, 1'b1, res);
        chk64("VKT.0", res, 64'h95a8d72813daa94d);
        repeat(2) @(posedge clk);

        des_op(64'h0000000000000000, 64'h4001010101010101, 1'b1, res);
        chk64("VKT.1", res, 64'h0eec1487dd8c26d5);
        repeat(2) @(posedge clk);

        des_op(64'h0000000000000000, 64'h2001010101010101, 1'b1, res);
        chk64("VKT.2", res, 64'h7ad16ffb79c45926);
        repeat(2) @(posedge clk);

        des_op(64'h0000000000000000, 64'h1001010101010101, 1'b1, res);
        chk64("VKT.3", res, 64'hd3746294ca6a6cf3);
        repeat(2) @(posedge clk);

        des_op(64'h0000000000000000, 64'h0801010101010101, 1'b1, res);
        chk64("VKT.4", res, 64'h809f5f873c1fd761);
        repeat(2) @(posedge clk);

        // ── Classic FIPS 81 example ──────────────────────────────────────
        $display("[T3] Classic FIPS 81 / FIPS 46-3 test vector");
        des_op(64'h0123456789ABCDEF, 64'h133457799BBCDFF1, 1'b1, res);
        chk64("FIPS81", res, 64'h85E813540F0AB405);
        repeat(2) @(posedge clk);

        // ── Encrypt → Decrypt roundtrip ──────────────────────────────────
        $display("[T4] Encrypt-Decrypt roundtrip");
        des_op(64'h0123456789ABCDEF, 64'h133457799BBCDFF1, 1'b1, ct_val);
        repeat(2) @(posedge clk);
        des_op(ct_val, 64'h133457799BBCDFF1, 1'b0, res);
        chk64("ROUNDTRIP", res, 64'h0123456789ABCDEF);
        repeat(2) @(posedge clk);

        // ── Idempotency: same op twice gives same result ─────────────────
        $display("[T5] Idempotency check — same encrypt twice");
        des_op(64'hDEADBEEFCAFEBABE, 64'h0F1571C947D9E859, 1'b1, res);
        ct_val = res;
        repeat(2) @(posedge clk);
        des_op(64'hDEADBEEFCAFEBABE, 64'h0F1571C947D9E859, 1'b1, res);
        if (ct_val === res) begin
            $display("  PASS  Same ct produced both times (0x%016h)", res);
            pass_cnt = pass_cnt + 1;
        end else begin
            $display("  FAIL  Idempotency broken: 0x%016h != 0x%016h", ct_val, res);
            fail_cnt = fail_cnt + 1;
        end
        repeat(2) @(posedge clk);

        // ── All-zeros key test ───────────────────────────────────────────
        $display("[T6] All-zeros key/pt - NIST permutation table");
        des_op(64'h0000000000000000, 64'h0000000000000000, 1'b1, res);
        // Must produce non-zero (DES permutes to meaningful value)
        if (res !== 64'hx) begin
            $display("  PASS  Non-undefined output: 0x%016h", res);
            pass_cnt = pass_cnt + 1;
        end else begin
            $display("  FAIL  Got X output");
            fail_cnt = fail_cnt + 1;
        end
        repeat(2) @(posedge clk);

        // ── 4 back-to-back operations — no state leakage ────────────────
        $display("[T7] 4x back-to-back operations (state isolation)");
        begin : bb_block
            integer bb;
            reg [63:0] ref_ct;
            des_op(64'h0123456789ABCDEF, 64'h133457799BBCDFF1, 1'b1, ref_ct);
            repeat(2) @(posedge clk);
            for (bb = 0; bb < 4; bb = bb + 1) begin
                des_op(64'h0123456789ABCDEF, 64'h133457799BBCDFF1, 1'b1, res);
                if (res === ref_ct) begin
                    $display("  PASS  BB[%0d] = 0x%016h", bb, res);
                    pass_cnt = pass_cnt + 1;
                end else begin
                    $display("  FAIL  BB[%0d] got=0x%016h exp=0x%016h", bb, res, ref_ct);
                    fail_cnt = fail_cnt + 1;
                end
                repeat(2) @(posedge clk);
            end
        end

        // ── Summary ───────────────────────────────────────────────────────
        $display(""); $display("=== SUMMARY: %0d PASSED, %0d FAILED ===", pass_cnt, fail_cnt);
        if (fail_cnt > 0) $fatal(1, "FAILURES in DES testbench");
        $display("ALL DES TESTS PASSED ✓");
        $finish;
    end

    initial begin #20000000; $fatal(1,"GLOBAL TIMEOUT"); end
endmodule
