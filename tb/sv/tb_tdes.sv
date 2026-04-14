// ============================================================
//  tb_tdes.sv — Triple-DES testbench (iverilog -g2012)
//  NIST SP 800-20 Table B.1 vectors
// ============================================================
`timescale 1ns/1ps
module tb_tdes;

    reg        clk, rst_n;
    reg [63:0] block;
    reg [191:0] key;
    reg [1:0]  mode;
    reg        load;
    wire [63:0] result;
    wire        done;

    initial clk = 0;
    always #5 clk = ~clk;

    tdes_core dut (.*);

    integer tdes_t;
    reg [63:0] res;
    task tdes_op;
        input [191:0] k; input [63:0] blk; input [1:0] m;
        output [63:0] out;
        begin
            @(posedge clk);
            key=k; block=blk; mode=m; load=1'b1;
            @(posedge clk); load=1'b0;
            out=64'hx;
            for (tdes_t=0; tdes_t<200; tdes_t=tdes_t+1) begin
                @(posedge clk);
                if (done) begin out=result; tdes_t=200; end
            end
            if (out===64'hx) $fatal(1,"TIMEOUT in 3DES");
        end
    endtask

    integer pass_cnt, fail_cnt;
    task chk64t;
        input [63:0] got, exp;
        input [127:0] lbl;
        begin
            if (got===exp) begin
                $display("  PASS  [%0s] 0x%016h", lbl, got); pass_cnt=pass_cnt+1;
            end else begin
                $display("  FAIL  [%0s] got=0x%016h  exp=0x%016h", lbl, got, exp); fail_cnt=fail_cnt+1;
            end
        end
    endtask

    initial begin
        $dumpfile("tb_tdes.vcd"); $dumpvars(0,tb_tdes);
        $display("=== 3DES Testbench ==="); $display("");
        pass_cnt=0; fail_cnt=0;
        rst_n=0; load=0; block=0; key=0; mode=0;
        repeat(4) @(posedge clk); rst_n=1; @(posedge clk);

        // NIST SP 800-20 Table B.1
        $display("[T1] 3TDEA EDE encrypt");
        tdes_op(192'h0123456789abcdef23456789abcdef01456789abcdef0123,
                64'h6bc1bee22e409f96, 2'b00, res);
        chk64t(res, 64'h714772f339841d34, "3TDEA-ENC");
        repeat(2) @(posedge clk);

        // Encrypt-decrypt roundtrip
        $display("[T2] 3TDEA EDE roundtrip");
        begin
            reg [63:0] ct_val;
            tdes_op(192'h0123456789abcdef23456789abcdef01456789abcdef0123,
                    64'h6bc1bee22e409f96, 2'b00, ct_val);
            repeat(2) @(posedge clk);
            tdes_op(192'h0123456789abcdef23456789abcdef01456789abcdef0123,
                    ct_val, 2'b01, res);
            chk64t(res, 64'h6bc1bee22e409f96, "3TDEA-RT");
        end
        repeat(2) @(posedge clk);

        $display(""); $display("=== SUMMARY: %0d PASSED, %0d FAILED ===", pass_cnt, fail_cnt);
        if (fail_cnt>0) $fatal(1,"3DES FAILURES"); $display("ALL 3DES TESTS PASSED ✓"); $finish;
    end
    initial begin #50000000; $fatal(1,"TIMEOUT"); end
endmodule
