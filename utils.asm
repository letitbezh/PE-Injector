
ifndef UTILS_ASM_
UTILS_ASM_ MACRO
ENDM


my_strcmp PROC NEAR

    push edi
    push esi
    push ebx                

loop_beg:
    cmp BYTE ptr [edi], 0
    jz  loop_end            
    mov bl, BYTE ptr [edi]
    cmp BYTE ptr [esi], bl
    jnz loop_end            
    inc edi
    inc esi
    jmp loop_beg

loop_end:
    movzx eax, BYTE ptr [edi]
    movzx ebx, BYTE ptr [esi]
    sub   eax, ebx

    pop ebx
    pop esi
    pop edi                 

    ret
my_strcmp ENDP


my_memcpy PROC NEAR

    push edi
    push esi
    push ebx                

    test edi, edi           
    je   lbl_result
    test esi, esi           
    je   lbl_result
    test edx, edx           
    je   lbl_result
    xor  ecx, ecx
    xor  ebx, ebx

lbl_loop:
    mov bl, BYTE ptr [esi + ecx]
    mov BYTE ptr [edi + ecx], bl
    inc ecx
    cmp ecx, edx
    jb  lbl_loop

lbl_result:
    mov eax, edi

    pop ebx
    pop esi
    pop edi                

    ret
my_memcpy ENDP


my_memset PROC NEAR

    push ebx
    push edx

    mov  eax, edi
    mov  ecx, edi
    lea  ebx, [edi + edx]
    test edi, edi          
    je   lbl_end

lbl_loop:
    mov edx, esi
    mov BYTE ptr [ecx], dl
    inc ecx
    cmp ecx, ebx
    jb  lbl_loop

lbl_end:
    pop edx
    pop ebx

    ret
my_memset ENDP


ceil_align PROC NEAR USES edi esi nbr:DWORD, alignment:DWORD

    mov edi, nbr
    mov esi, alignment
    xor eax, eax
ceil_align_loop:
    cmp eax, edi
    jae ceil_align_loop_end  
    add eax, esi
    jmp ceil_align_loop
ceil_align_loop_end:

    ret
ceil_align ENDP

endif                        
