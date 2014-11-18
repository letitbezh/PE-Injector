
ifndef	SEARCH_K32_ASM_
SEARCH_K32_ASM_	MACRO
ENDM

    and     esi, 0FFFF0000h             ; mask address inside k32.dll to get page aligned like sections.

search_k32:
    sub     esi, 1000h                  ; Going back and back, keeping the page/section alignment.
    cmp     word ptr [esi], "ZM"        ; Looking for the "MZ" signature of a DOS header. "ZM" for endianess.
    jne     search_k32

    mov     imageBase, esi              ; imageBase = Real BaseAdress (for sure).

    add     esi, [esi + 3Ch]            ; esi -> IMAGE_NT_HEADERS
    cmp     word ptr [esi], "EP"
    jne     exit

    add     esi, 18h                    ; esi -> IMAGE_OPTIONAL_HEADER

    cmp     word ptr [esi], 10bh        ; 10bh = IMAGE_OPTIONAL_HEADER magic number for 32bits programs
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

endif	; SEARCH_K32_ASM_