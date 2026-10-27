	.intel_syntax noprefix
	.text
	push ebp
	mov ebp, esp
	pushal
	popal
	inc eax
	dec ecx
	mov eax, dword ptr [ebp + 8]
	mov ax, word ptr [esi + 4*ecx - 2]
	lea edi, [eax + eax*2]
	mov eax, dword ptr [0x1234]
	mov dword ptr gs:[0x14], eax
	lock xadd dword ptr [ecx], edx
	rep movsd dword ptr es:[edi], dword ptr [esi]
	cdq
	idiv ecx
	imul eax, dword ptr [ebx], 10
	movzx ecx, word ptr [edx]
	fld dword ptr [esp + 4]
	fadd st, st(1)
	fstp qword ptr [ebp - 8]
	fild dword ptr [eax]
	fistp dword ptr [eax]
	fxch st(2)
	fnstsw ax
	int 0x80
	jmp eax
	call dword ptr [eax + 4]
	aaa
	daa
	push cs
	pop es
	movd mm0, eax
	paddw mm0, mm1
	emms
	addps xmm0, xmm1
	cvtsi2ss xmm0, eax
	leave
	ret
