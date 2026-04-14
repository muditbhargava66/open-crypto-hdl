// ============================================================
//  tb_chacha20.sv — ChaCha20 self-checking testbench
//  RFC 8439 §A official test vectors
//  iverilog -g2012 compatible
// ============================================================
`timescale 1ns/1ps
module tb_chacha20;

    reg         clk, rst_n;
    reg  [255:0] key;
    reg   [95:0] nonce;
    reg   [31:0] counter;
    reg          valid_in;
    wire [511:0] keystream;
    wire         valid_out;

    initial clk = 0;
    always #5 clk = ~clk;

    chacha20_core dut (
        .clk(clk), .rst_n(rst_n), .key(key), .nonce(nonce),
        .counter(counter), .valid_in(valid_in),
        .keystream(keystream), .valid_out(valid_out)
    );

    // -------------------------------------------------------------------
    // Unpack 512-bit keystream into 16 × 32-bit LE words.
    // ChaCha20 word[i] is stored at keystream[i*32+31 : i*32].
    // The 32-bit integer value equals what RFC 8439 calls word[i].
    // -------------------------------------------------------------------
    reg [31:0] w [0:15];
    task unpack_ks; input [511:0] s; begin
        w[ 0]=s[ 31:  0]; w[ 1]=s[ 63: 32]; w[ 2]=s[ 95: 64]; w[ 3]=s[127: 96];
        w[ 4]=s[159:128]; w[ 5]=s[191:160]; w[ 6]=s[223:192]; w[ 7]=s[255:224];
        w[ 8]=s[287:256]; w[ 9]=s[319:288]; w[10]=s[351:320]; w[11]=s[383:352];
        w[12]=s[415:384]; w[13]=s[447:416]; w[14]=s[479:448]; w[15]=s[511:480];
    end endtask

    reg [511:0] ks_result;
    task chacha_block; input [255:0] k; input [95:0] n; input [31:0] ctr;
        integer t; begin
            @(posedge clk); key=k; nonce=n; counter=ctr; valid_in=1'b1;
            @(posedge clk); valid_in=1'b0; ks_result=512'd0;
            for (t=0; t<300; t=t+1) begin
                @(posedge clk);
                if (valid_out) begin ks_result=keystream; t=300; end
            end
            if (ks_result===512'd0) $fatal(1,"TIMEOUT: valid_out never asserted");
        end
    endtask

    integer pass_cnt, fail_cnt;
    task chk; input [63:0] idx; input [31:0] got; input [31:0] exp; begin
        if (got===exp) begin
            $display("  PASS  w[%0d] = 0x%08h", idx, got); pass_cnt=pass_cnt+1;
        end else begin
            $display("  FAIL  w[%0d] got=0x%08h  exp=0x%08h", idx, got, exp);
            fail_cnt=fail_cnt+1;
        end
    end endtask

    reg [511:0] res0, res1, res2, res3;

    initial begin
        $dumpfile("tb_chacha20.vcd"); $dumpvars(0, tb_chacha20);
        $display(""); $display("=== ChaCha20 Testbench — RFC 8439 official vectors ==="); $display("");
        pass_cnt=0; fail_cnt=0;
        rst_n=0; valid_in=0; key=0; nonce=0; counter=0;
        repeat(4) @(posedge clk); rst_n=1; @(posedge clk);

        // ── T1: RFC 8439 Appendix A — all-zeros key/nonce, ctr=0 ────────
        $display("[T1] All-zeros key/nonce/ctr=0  (RFC 8439 Appendix A §1)");
        chacha_block(256'd0, 96'd0, 32'd0); unpack_ks(ks_result);
        // Expected output words from RFC 8439 Appendix A, Test Vector 1
        chk( 0, w[ 0], 32'hade0b876); chk( 1, w[ 1], 32'h903df1a0);
        chk( 2, w[ 2], 32'he56a5d40); chk( 3, w[ 3], 32'h28bd8653);
        chk( 4, w[ 4], 32'hb819d2bd); chk( 5, w[ 5], 32'h1aed8da0);
        chk( 6, w[ 6], 32'hccef36a8); chk( 7, w[ 7], 32'hc70d778b);
        chk( 8, w[ 8], 32'h7c5941da); chk( 9, w[ 9], 32'h8d485751);
        chk(10, w[10], 32'h3fe02477); chk(11, w[11], 32'h374ad8b8);
        chk(12, w[12], 32'hf4b8436a); chk(13, w[13], 32'h1ca11815);
        chk(14, w[14], 32'h69b687c3); chk(15, w[15], 32'h8665eeb2);
        repeat(2) @(posedge clk);

        // ── T2: all-zeros key/nonce, ctr=1 ───────────────────────────────
        $display("[T2] All-zeros key/nonce, ctr=1  (RFC 8439 Appendix A §1)");
        chacha_block(256'd0, 96'd0, 32'd1); unpack_ks(ks_result);
        chk( 0, w[ 0], 32'hbee7079f); chk( 1, w[ 1], 32'h7a385155);
        chk( 2, w[ 2], 32'h7c97ba98); chk( 3, w[ 3], 32'h0d082d73);
        chk( 4, w[ 4], 32'ha0290fcb); chk( 5, w[ 5], 32'h6965e348);
        chk( 6, w[ 6], 32'h3e53c612); chk( 7, w[ 7], 32'hed7aee32);
        repeat(2) @(posedge clk);

        // ── T3: RFC 8439 §A.2 — AEAD test vector key/nonce, ctr=1 ──────
        $display("[T3] RFC 8439 §A.2 key/nonce, ctr=1");
        chacha_block(
            256'h000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f,
            96'h000000090000004a00000000, 32'd1);
        unpack_ks(ks_result);
        chk(0, w[0], 32'he4e7f110); chk(1, w[1], 32'h15593bd1);
        chk(2, w[2], 32'h1fdd0f50); chk(3, w[3], 32'hc47120a3);
        repeat(2) @(posedge clk);

        // ── T4: Idempotency ───────────────────────────────────────────────
        $display("[T4] Idempotency — same inputs produce same output");
        chacha_block(256'hdeadbeef, 96'hcafebabe, 32'd7); res0=ks_result;
        repeat(2) @(posedge clk);
        chacha_block(256'hdeadbeef, 96'hcafebabe, 32'd7); res1=ks_result;
        if (res0===res1) begin $display("  PASS  Identical outputs confirmed"); pass_cnt=pass_cnt+1; end
        else             begin $display("  FAIL  Idempotency broken!");         fail_cnt=fail_cnt+1; end

        // ── T5: Counter uniqueness ────────────────────────────────────────
        $display("[T5] Counter uniqueness — ctr 0-3 all distinct");
        chacha_block(256'hdeadbeef, 96'hcafebabe, 32'd0); res0=ks_result; repeat(2) @(posedge clk);
        chacha_block(256'hdeadbeef, 96'hcafebabe, 32'd1); res1=ks_result; repeat(2) @(posedge clk);
        chacha_block(256'hdeadbeef, 96'hcafebabe, 32'd2); res2=ks_result; repeat(2) @(posedge clk);
        chacha_block(256'hdeadbeef, 96'hcafebabe, 32'd3); res3=ks_result;
        if (res0!==res1 && res0!==res2 && res0!==res3 &&
            res1!==res2 && res1!==res3 && res2!==res3) begin
            $display("  PASS  All 4 blocks distinct"); pass_cnt=pass_cnt+1;
        end else begin $display("  FAIL  Duplicate keystream blocks!"); fail_cnt=fail_cnt+1; end

        // ── T6: Non-zero output sanity ────────────────────────────────────
        $display("[T6] Non-zero keystream for all-0xFF key");
        chacha_block(256'hffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
                     96'hffffff000000000000000000, 32'd0);
        if (ks_result!==512'd0) begin $display("  PASS  Non-zero confirmed"); pass_cnt=pass_cnt+1; end
        else                    begin $display("  FAIL  All-zero keystream!"); fail_cnt=fail_cnt+1; end

        // ── Summary ───────────────────────────────────────────────────────
        $display(""); $display("=== SUMMARY: %0d PASSED, %0d FAILED ===", pass_cnt, fail_cnt);
        if (fail_cnt>0) $fatal(1,"FAILURES detected in ChaCha20 testbench");
        $display("ALL CHACHA20 TESTS PASSED ✓"); $finish;
    end

    initial begin #20000000; $fatal(1,"GLOBAL TIMEOUT"); end
endmodule
