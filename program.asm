.data
msg:    .asciiz "Hi"
numd:   .dword 899
num1:   .word 15
num2:   .half 25
space:  .space 6
num3:   .byte 4

.text
main:
    addi x1, x0, 5
    addi x2, x0, 10
    add  x3, x1, x2
    blt x3, x0, main