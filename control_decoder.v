`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Company: 
// Engineer: 
// 
// Create Date: 04/09/2025 08:10:13 PM
// Design Name: 
// Module Name: control_decoder
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

module control_decoder (
    input [31:0] instruction,
    input [5:0] func_code,
    output reg reg_dst,
    output reg alu_src,
    output reg mem_to_reg,
    output reg reg_write,
    output reg mem_read,
    output reg mem_write,
    output reg branch,
    output reg branch_not_equal,
    output reg [1:0] alu_op,
    output reg mfhi_en,
    output reg mflo_en
);

    wire [5:0] opcode;
    assign opcode = instruction[31:26];

    always @(*) begin
        mfhi_en = 0;
        mflo_en = 0;
        reg_dst     = 0;
        alu_src     = 0;
        mem_to_reg  = 0;
        reg_write   = 0;
        mem_read    = 0;
        mem_write   = 0;
        branch      = 0;
        branch_not_equal = 0;
        alu_op      = 2'b00;
        
        case (opcode)
            6'b000000: begin // R-type
                case (func_code)
                    6'b011000, // mult
                    6'b011001, // multu
                    6'b011010, // div
                    6'b011011: // divu
                        reg_write = 0;
                    6'b010000: begin
                        reg_write = 1;
                        reg_dst = 1;
                        mfhi_en = 1;
                    end
                    6'b010010: begin
                        reg_write = 1;
                        reg_dst = 1;
                        mflo_en = 1;
                    end
                    default: begin
                        reg_dst     = 1;
                        alu_src     = 0;
                        mem_to_reg  = 0;
                        reg_write   = 1;
                        mem_read    = 0;
                        mem_write   = 0;
                        branch      = 0;
                        branch_not_equal = 0;
                        alu_op      = 2'b10;
                    end
                endcase
            end
            6'b100011: begin // LW
                reg_dst     = 0;
                alu_src     = 1;
                mem_to_reg  = 1;
                reg_write   = 1;
                mem_read    = 1;
                mem_write   = 0;
                branch      = 0;
                branch_not_equal = 0;
                alu_op      = 2'b00;
            end
            6'b101011: begin // SW
                reg_dst     = 0;  
                alu_src     = 1;
                mem_to_reg  = 0;
                reg_write   = 0;
                mem_read    = 0;
                mem_write   = 1;
                branch      = 0;
                branch_not_equal = 0;
                alu_op      = 2'b00;
            end
            6'b000011: begin // JAL
                reg_dst     = 0;  
                alu_src     = 0;
                mem_to_reg  = 0;
                reg_write   = 1;
                mem_read    = 0;
                mem_write   = 0;
                branch      = 0;
                branch_not_equal = 0;
                alu_op      = 2'b01; // Don't care
            end
            6'b000100: begin // BEQ
                reg_dst     = 0;  
                alu_src     = 0;
                mem_to_reg  = 0;
                reg_write   = 0;
                mem_read    = 0;
                mem_write   = 0;
                branch      = 1;
                branch_not_equal = 0;
                alu_op      = 2'b01;
            end
            6'b000101: begin // BNE
                reg_dst     = 0;
                alu_src     = 0;
                mem_to_reg  = 0;
                reg_write   = 0;
                mem_read    = 0;
                mem_write   = 0;
                branch      = 0;
                branch_not_equal = 1;
                alu_op      = 2'b01;
            end
            6'b001000: begin // ADDI
                reg_dst     = 0;
                alu_src     = 1;
                mem_to_reg  = 0;
                reg_write   = 1;
                mem_read    = 0;
                mem_write   = 0;
                branch      = 0;
                branch_not_equal = 0;
                alu_op      = 2'b00;
            end
            6'b001000: begin // SUBI
                reg_dst     = 0;
                alu_src     = 1;
                mem_to_reg  = 0;
                reg_write   = 1;
                mem_read    = 0;
                mem_write   = 0;
                branch      = 0;
                branch_not_equal = 0;
                alu_op      = 2'b01;
            end
            default: begin
                reg_dst     = 0;
                alu_src     = 0;
                mem_to_reg  = 0;
                reg_write   = 0;
                mem_read    = 0;
                mem_write   = 0;
                branch      = 0;
                branch_not_equal = 0;
                alu_op      = 2'b00;
            end
        endcase
    end

endmodule