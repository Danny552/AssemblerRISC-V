label1:
addi x1, x0, 5
beq x1, x0, label1
label2:
sub x2, x1, x0
beq x2, x0, label2
sw x2, 0(x0)
lw x3, 0(x0)
addi x4, x3, 10
