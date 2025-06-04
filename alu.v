`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Company: 
// Engineer: 
// 
// Create Date: 04/10/2025 01:12:28 AM
// Design Name: 
// Module Name: alu
// Project Name: 
// Target Devices: 
// Tool Versions: 
// Description: 
// 
// Dependencies: 
// 
// Revision:
// Revision 0.01 - File Created
// Additional Comments:
// 
//////////////////////////////////////////////////////////////////////////////////


module alu(
        input [31:0] a, b, input [3:0] alu_control, input [5:0] shift, output reg [31:0] out, hi, lo, output zero
    );
    
    assign zero = (out == 0);
    
    always@(*) begin
        case (alu_control)
            4'b0000: out = a & b;
            4'b0001: out = a | b;
            4'b0010: out = a + b;
            4'b0011: out = a ^ b;
            4'b0100: out = ~ (a | b);
            4'b0101: out = a - b;
            4'b0110: out = ($signed(a) < $signed(b)) ? 1: 0;
            4'b0111: out = (a < b) ? 1: 0;
            4'b1001: out = b << shift;
            4'b1010: out = b >> shift;
            4'b1011: out = b >>> shift;
            4'b1100: {hi, lo} = $signed(a) * $signed(b);
            4'b1101: {hi, lo} = a * b;
            4'b1110: begin
                hi = $signed(a) % $signed(b);
                lo = $signed(a) / $signed(b);
            end
            4'b1111: begin
                hi = a % b;
                lo = a / b;
            end
            default: out = 0;
        endcase
    end
endmodule
