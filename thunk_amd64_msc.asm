section .text

	REG_ARG_SAVE_SIZE equ 8 + 4 * 8 + 4 * 16 ; padding + 4 gp regs + 4 xmm regs
	REG_ARG_HOME_SIZE equ 4 * 8
	STACK_FRAME_SIZE  equ REG_ARG_SAVE_SIZE + REG_ARG_HOME_SIZE

	extern targetFunc
	extern hookEnterFunc
	extern hookLeaveFunc
	extern hookExceptionFunc
	extern hookRet

thunk_entry:

	; standard prologue (leaves rpb 16-byte aligned)

	push    rbp
	mov     rbp, rsp
	sub     rsp, STACK_FRAME_SIZE

	; save all arg registers (xmm must be 16-byte aligned)

	mov     [rbp - 16 - 8 * 0], rcx
	mov     [rbp - 16 - 8 * 1], rdx
	mov     [rbp - 16 - 8 * 2], r8
	mov     [rbp - 16 - 8 * 3], r9
	movdqa  [rbp - 16 - 8 * 4 - 16 * 0], xmm0
	movdqa  [rbp - 16 - 8 * 4 - 16 * 1], xmm1
	movdqa  [rbp - 16 - 8 * 4 - 16 * 2], xmm2
	movdqa  [rbp - 16 - 8 * 4 - 16 * 3], xmm3

	; call the hook-enter function

	mov     rcx, targetFunc
	mov     rdx, rbp
	mov     r8, [rbp + 8]
	mov     rax, hookEnterFunc
	call    rax

	; restore all arg registers

	mov     rcx,  [rbp - 16 - 8 * 0]
	mov     rdx,  [rbp - 16 - 8 * 1]
	mov     r8,   [rbp - 16 - 8 * 2]
	mov     r9,   [rbp - 16 - 8 * 3]
	movdqa  xmm0, [rbp - 16 - 8 * 4 - 16 * 0]
	movdqa  xmm1, [rbp - 16 - 8 * 4 - 16 * 1]
	movdqa  xmm2, [rbp - 16 - 8 * 4 - 16 * 2]
	movdqa  xmm3, [rbp - 16 - 8 * 4 - 16 * 3]

	; undo prologue

	add     rsp, STACK_FRAME_SIZE
	pop     rbp

	; replace return pointer

	mov     rax, hookRet
	mov     [rsp], rax

	; jump to target function

	mov     rax, targetFunc
	jmp     rax

hook_ret:

	; rax now holds the original retval

	; re-create our stack frame (compensating ret from targetFunc)

	sub     rsp, 8  ; <<< hook_ret
	push    rbp
	mov     rbp, rsp
	sub     rsp, STACK_FRAME_SIZE

	; save the original retval

	mov     [rbp - 8], rax

	; call the hook-leave function

	mov     rcx, targetFunc
	mov     rdx, rbp
	mov     r8, rax
	mov     rax, hookLeaveFunc
	call    rax

	; rax now holds the original return pointer

	; restore the original return pointer and retval

	mov     [rbp + 8], rax
	mov     rax, [rbp - 8]

	; standard epilogue

	add     rsp, STACK_FRAME_SIZE
	pop     rbp
	ret

seh_handler:

	; save rdx (thunk.rbp = rdx - 16)

	push    rdx  ; <<< seh_handler

	; call the hook-exception function

	mov     rax, hookExceptionFunc
	call    rax

	; rax now holds the original return pointer

	pop     rdx

	; restore the original return pointer

	mov     [rdx - 16 + 8], rax

	; return ExceptionContinueExecution

	mov     rax, 0
	ret
