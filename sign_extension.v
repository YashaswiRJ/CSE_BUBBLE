`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Company: 
// Engineer: 
// 
// Create Date: 04/10/2025 01:27:35 AM
// Design Name: 
// Module Name: sign_extension
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


module sign_extension(
        input [15:0] imm, output [31:0] imm_extended
    );
    assign imm_extended = {{16{imm[15]}}, imm};
endmodule
