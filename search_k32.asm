
ifndef SEARCH_K32_ASM_
SEARCH_K32_ASM_ MACRO
ENDM


    and  esi, 0FFFF0000h                          

    cmp  word ptr [esi], "ZM"                    
	je   stop_search_k32
search_k32:
    sub  esi, 10000h                              
    cmp  word ptr [esi], "ZM"                     
    jne  search_k32
stop_search_k32:

    mov  imageBase, esi                     

    add  esi, [esi + 3Ch]                         
    cmp  word ptr [esi], "EP"
    jne  exit

    add  esi, 18h                                 

    cmp  word ptr [esi], 10bh                     
    jne  exit

    add  esi, 60h                               
    mov  esi, dword ptr [esi]                    

    add  esi, imageBase                           



    mov  edx, [esi + 20h]                        
    add  edx, imageBase                          

    push edx                                      
    push esi                                      
    lea  esi, [ebx + offset getProcAddress_name]  
    xor  ecx, ecx                                 
	sub ecx,sizeof dword 
browse_export_names:
	add  ecx, sizeof dword
    mov  edi, [edx + ecx]                         
    add  edi, imageBase                          
                            

    call my_strcmp                              
    cmp  eax, 0
    jne  browse_export_names                    


    pop  esi                                  

    mov  edx, [esi + 1ch]                       
	;sub ecx,4
    add  edx, ecx                               
    add  edx, imageBase                        

    mov  edx, [edx]                             
    add  edx, imageBase                         
    mov  getProcAddress_addr , edx



    pop  edx                                     

    push esi                                     
    lea  esi, [ebx + offset loadLibrary_name]    
    xor  ecx, ecx                               
	sub ecx, sizeof dword   
browse_export_names2:
	add  ecx, sizeof dword 
    mov  edi, [edx + ecx]                       
    add  edi, imageBase                           
                         

    call my_strcmp                               
    cmp  eax, 0
    jne  browse_export_names2                 


    pop  esi                                   

    mov  edx, [esi + 1ch]                     
    ;sub  ecx, 4                                  
    add  edx, ecx                                
    add  edx, imageBase                          

    mov  edx, [edx]                               
    add  edx, imageBase                           
    mov  loadLibrary_addr, edx
	;mov eax,7c801d7bh
	;mov loadLibrary_addr,eax
	;mov getProcAddress_addr,7c80ae40h


endif ; SEARCH_K32_ASM_
