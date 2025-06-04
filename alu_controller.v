`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Company: 
// Engineer: 
// 
// Create Date: 04/10/2025 12:53:08 AM
// Design Name: 
// Module Name: alu_controller
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


module alu_controller(
        input [1:0] alu_op, input [5:0] func_code, output reg [3:0] alu_control 
    );
    
    always@(*) begin
        case (alu_op)
            2'b00: alu_control = 4'b0010;
            2'b01: alu_control = 4'b0101;
            2'b10:
                case (func_code) 
                    6'b000000: alu_control = 4'b1001; // sll
                    6'b000010: alu_control = 4'b1010; // srl
                    6'b000011: alu_control = 4'b1011; // sra (sla dne)
                    6'b100000: alu_control = 4'b0010; // add
                    6'b100001: alu_control = 4'b0010; // addu
                    6'b100010: alu_control = 4'b0101; // sub
                    6'b100011: alu_control = 4'b0101; // subu
                    6'b100100: alu_control = 4'b0000; // and
                    6'b100101: alu_control = 4'b0001; // or
                    6'b100110: alu_control = 4'b0011; // xor
                    6'b100111: alu_control = 4'b0100; // nor
                    6'b101010: alu_control = 4'b0110; // slt
                    6'b101011: alu_control = 4'b0111; // sltu
                    6'b011000: alu_control = 4'b1100; // mult
                    6'b011001: alu_control = 4'b1101; // multu
                    6'b011010: alu_control = 4'b1110; // div
                    6'b011011: alu_control = 4'b1111; // divu
                    default: alu_control = 4'b0000;
                endcase
            default: alu_control = 4'b0000;
        endcase 
    end
endmodule
