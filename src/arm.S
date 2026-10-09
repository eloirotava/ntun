/* Entrada do programa e chamada de sistema, ARM EABI (Linux). O resto do
 * programa e Thumb-2; o ligador resolve as chamadas entre os dois modos.
 * Chamada de sistema: numero em r7, argumentos em r0-r5, svc #0; o kernel
 * devolve -errno direto em r0. */
	.syntax	unified
	.text
	.arm

	.globl	__start
	.type	__start, %function
__start:
	ldr	r0, [sp]		@ argc
	add	r1, sp, #4		@ argv
	bic	sp, sp, #7
	bl	main
	mov	r7, #248		@ exit_group
	svc	#0

/* long raw_syscall(long n, long a, long b, long c, long d, long e, long f)
 * r0 = n, r1-r3 = a, b, c; d, e, f na pilha do chamador */
	.globl	raw_syscall
	.type	raw_syscall, %function
raw_syscall:
	push	{r4, r5, r7, lr}
	mov	r7, r0
	mov	r0, r1
	mov	r1, r2
	mov	r2, r3
	ldr	r3, [sp, #16]
	ldr	r4, [sp, #20]
	ldr	r5, [sp, #24]
	svc	#0
	pop	{r4, r5, r7, pc}

/* pilha nao executavel */
	.section .note.GNU-stack,"",%progbits
