`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Company: 
// Engineer: 
// 
// Create Date: 04/09/2025 08:59:26 PM
// Design Name: 
// Module Name: register_file
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


module register_file(
        input clk, reg_write,
        input [4:0] read_reg1, read_reg2, write_reg,
        input [31:0] write_data,
        output [31:0] read_data1, read_data2
    );
    
    reg [31:0] register [31:0];
    
    assign read_data1 = register[read_reg1];
    assign read_data2 = register[read_reg2];
    
    integer i;
    initial begin
        for (i = 0; i < 32; i = i + 1) begin
            register[i] = 32'b0;  // Initialize all registers to 0
        end
    end

    always@(posedge clk)begin
        register[0] <= 0;
        if(reg_write && write_reg != 0) begin
            register[write_reg] <= write_data;
        end
    end
     
endmodule
