`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Company: 
// Engineer: 
// 
// Create Date: 04/09/2025 05:44:37 PM
// Design Name: 
// Module Name: datapath
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


module datapath(input clk, input rst, input inst_load, input data_load, input [31:0] data, output reg [31:0] pc, input curr_inst);
    
    wire [31:0] instructions;
    reg we_i = 1'b0;
    reg we_d = 1'b0;
    wire [31:0] d = 32'b0;
    wire take_branch;
    wire take_jump;
    wire take_jal; // jal
    wire take_jr;
    wire [31:0] branch_offset;
    
    assign take_branch = (branch && zero) || (branch_not_equal && ~zero);
    assign take_jal = (opcode == 6'b000011);
    assign take_jump = (opcode == 6'b000010) || (opcode == 6'b000011); // j or jal
    assign take_jr = (opcode == 6'b000000 && func_code == 6'b001000);
    assign branch_offset ={{14{imm[15]}}, imm, 2'b00}; 
    
//    program_counter pc_count(
//        .clk(clk), 
//        .rst(rst), 
//        .pc(pc), 
//        .take_branch(take_branch), 
//        .take_jump(take_jump),
//        .take_jr(take_jr),
//        .jump_offset(offset),
//        .branch_offset(branch_offset),
//        .jr_addr(read_data1)
//        );

    always@(posedge clk or posedge rst)begin
        if (rst) 
            pc <= 32'b0;
        else if (take_branch)
            pc <= pc + branch_offset + 4;
        else if (take_jump)
            pc <= {pc[31:28], offset, 2'b00};
        else if(take_jr)
            pc <= read_data1;
        else 
            pc <= pc + 4;
    end
    
    dist_mem_gen_0 instruction_memory(
        .a(pc[11:2]),
        .dpra(pc[11:2]),
        .clk(clk),
        .we(we_i),
        .d(data),
        .dpo(instructions)
        );
   
        
    wire [5:0] opcode;
    wire [4:0] rs;
    wire [4:0] rt;
    wire [4:0] rd;
    wire [15:0] imm;
    wire [4:0] shamt;
    wire [5:0] func_code;
    wire [25:0] offset;
    
    assign opcode = instructions[31:26];
    assign rs = instructions[25:21];
    assign rt = instructions[20:16];
    assign rd = instructions[15:11];
    assign imm = instructions[15:0];
    assign shamt = instructions[10:6];
    assign func_code = instructions[5:0];
    assign offset = instructions[25:0];
    
    wire [31:0] sign_ext_imm;
    
    sign_extension se(.imm(imm), .imm_extended(sign_ext_imm));
    
    wire reg_dst, alu_src, mem_to_reg, reg_write, mem_read, mem_write, branch, branch_not_equal;
    wire [1:0] alu_op;
    wire mfhi_en, mflo_en;
    
    control_decoder ctrl(
        .instruction(instructions),
        .reg_dst(reg_dst),
        .alu_src(alu_src),
        .mem_to_reg(mem_to_reg),
        .reg_write(reg_write),
        .mem_read(mem_read),
        .mem_write(mem_write),
        .branch(branch),
        .branch_not_equal(branch_not_equal),
        .alu_op(alu_op),
        .mflo_en(mflo_en),
        .mfhi_en(mfhi_en)
    );
    
    wire [31:0] alu_result;
    
    wire [31:0] read_data1, read_data2;
    wire [4:0] write_reg;
    
    assign write_reg = mfhi_en ? rd : mflo_en ? rd : take_jal ? 5'd31 : reg_dst ? rd : rt;
    
    register_file rf(
        .clk(clk),
        .reg_write(reg_write),
        .read_reg1(rs),
        .read_reg2(rt),
        .write_reg(write_reg),
        .write_data(write_data),
        .read_data1(read_data1),
        .read_data2(read_data2)
    );
    
    wire [3:0] alu_control;
    
    alu_controller ac(
        .alu_op(alu_op),
        .func_code(func_code),
        .alu_control(alu_control)
    );
    
    wire [31:0] alu_input2;
    assign alu_input2 = alu_src ? sign_ext_imm: read_data2;
    wire zero;
    wire [31:0] hi, lo;
    
    alu alu(
        .a(read_data1),
        .b(alu_input2),
        .alu_control(alu_control),
        .shift(shamt),
        .out(alu_result),
        .hi(hi),
        .lo(lo),
        .zero(zero)
    );
    
    wire [31:0] memory_read_data;
    wire [31:0] pc_plus_4;
    assign pc_plus_4 = pc + 4; 
    
    wire [31:0] write_data;
    assign write_data = take_jal ? pc_plus_4 :(mem_to_reg ? memory_read_data : alu_result);
    
//    data_memory dmem(
//        .clk(clk), 
//        .memRead(mem_read),
//        .memWrite(mem_write),
//        .address(alu_result),
//        .write_data(read_data2),
//        .read_data(memory_read_data)
//    );
    wire [31:0] addr_data_mem;
    wire [31:0] addr_data_mem_to_write;
    assign addr_data_mem = data_load ? pc : alu_result;
    assign addr_data_mem_to_write = data_load ? data : read_data2;
    
    dist_mem_gen_0 data_memory(
        .clk(clk),
        .we(we_d),
        .d(addr_data_mem_to_write),
        .dpo(memory_read_data),
        .a(addr_data_mem),
        .dpra(alu_result)
    );
    
    
    always@(posedge clk) begin
        if(inst_load == 1'b1) begin
            we_i <= 1'b1;
        end
        else begin
            we_i <= 1'b0;
        end

        if(data_load == 1'b1 || mem_write) begin
           we_d <= 1'b1;
        end
        else begin
            we_d <= 1'b0;
        end
    end
endmodule
