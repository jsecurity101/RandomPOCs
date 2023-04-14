//Author: Jonathan Johnson

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
                if (!SetThreadToken(NULL, hDuplicate))
                {
                    std::cout << "[-] Impersonation Failed (" << GetLastError() << ").\n";
                }
                else
                {
                    printf("[*] Impersoantion Passed!\n");

                    if (!GetUserNameW(username, &username_len))
                    {
                        std::cout << "[-] GetUserName Failed (" << GetLastError() << ").\n";
                    }
                    else
                    {
                        std::wstring username_w(username);
                        std::string username_s(username_w.begin(), username_w.end());
                        std::cout << "[*] Impersonated username is: " << username_s << "\n";
                        
						RevertToSelf();
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