	.intel_syntax noprefix
	.text
	add r8, r9
	mov ax, cx
	mov al, byte ptr [r12 + 1]
	movabs rax, 0x1122334455667788
	mov rax, qword ptr fs:[0x28]
	lea rax, [rip + 0x100]
	lock add qword ptr [rax + 8*rbx + 0x12345678], 0x12345678
	rep movsb byte ptr es:[rdi], byte ptr [rsi]
	rep stosq qword ptr es:[rdi], rax
	repne scasb al, byte ptr es:[rdi]
	popcnt eax, ecx
	tzcnt rax, rbx
	lzcnt ecx, edx
	bswap r10
	cmovg eax, ebx
	setb cl
	movzx eax, byte ptr [rdi]
	movsx rax, word ptr [rsi + 2]
	movsxd rax, ecx
	imul rax, rbx, 100
	cqo
	idiv rcx
	xchg rax, rcx
	cmpxchg qword ptr [rdi], rsi
	syscall
	cpuid
	rdtsc
	pause
	ud2
	int3
	push 0x12
	pop r15
	ret 8
	shl rax, cl
	sar edx, 3
	ror r9d, 1
	bt eax, 5
	vaddps ymm0, ymm1, ymm2
	vmovdqu xmm3, xmmword ptr [rax]
	vpxor xmm0, xmm0, xmm0
	vfmadd231ps xmm1, xmm2, xmm3
	vzeroupper
	movaps xmm0, xmmword ptr [rsp + 16]
	cvtsi2sd xmm0, rax
	cvttsd2si eax, xmm1
	pshufb xmm0, xmm1
	addsd xmm0, qword ptr [rip + 0x40]
	ucomiss xmm0, xmm1
	sqrtsd xmm2, xmm3
	andnps xmm4, xmm5
	pxor xmm6, xmm7
	movq rax, xmm0
	movd xmm1, ecx
	crc32 eax, byte ptr [rdi]
	adc r11, -1
	sbb byte ptr [rbx], 1
	neg qword ptr [rsp]
	not r8d
	test sil, dil
	mov r8b, spl
	mov word ptr [rbx], 0x1234
	jmp qword ptr [rax*8 + 0x1000]
	call qword ptr [rip + 0x10]
	enter 0x10, 0
	leave
	nop dword ptr [rax + rax]
	xadd dword ptr [rcx], edx
	mfence
	prefetcht0 byte ptr [rdi]
	cmc
	std
	cld
