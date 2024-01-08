//Author: Jonathan Johnson
//References: Stack Overflow / MSDN - https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa

#include <Windows.h>
#include <iostream>
#pragma comment(lib,"ntdll.lib")
#include "structs.h"
#include <TlHelp32.h>

BOOL CreateProcessWithDuplication(DWORD ProcessId, DWORD ThreadId) {
    if (ThreadId == 0)
    {
        ThreadId = GetCurrentThreadId();
    }
    printf("[*] Changing the token of thread id %d\n", ThreadId);
    BOOL ret = FALSE;
    HANDLE hToken = NULL;
    HANDLE hThread = NULL;
    HANDLE dupToken = NULL;
    HANDLE hTokenThread = NULL;
    NTSTATUS status;
    STARTUPINFO si = { 0 };
    si.cb = sizeof STARTUPINFO;

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof PROCESS_INFORMATION);
    wchar_t process[] = L"C:\\Windows\\System32\\cmd.exe";

    //
   // -------------- Impersonation --------------
   //
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, ProcessId);
    if (hProcess == NULL)
    {
        printf("OpenProcess Failed (%d).\n", GetLastError());
        goto Cleanup;
    }
    printf("[*] OpenProcess was successful\n");
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken))
    {
        printf("OpenProcessToken Failed (%d).\n", GetLastError());
        goto Cleanup;
    }
    printf("[*] OpenProcessToken was successful\n");
    if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &dupToken))
    {
        std::cout << "DuplicateTokenEx Failed (" << GetLastError() << ").\n";
        goto Cleanup;
    }
    printf("[*] DuplicateTokenEx was successful\n");
    hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, ThreadId);
    if (hThread == NULL)
    {
        printf("OpenThread Failed (%d).\n", GetLastError());
        goto Cleanup;
    }
    printf("[*] OpenThread was successful\n");
    status = NtSetInformationThread(hThread, ThreadImpersonationToken, &dupToken, sizeof(HANDLE));
    if (status != 0)
    {
        printf("NtSetInformationThread Failed (%d).\n", status);
        goto Cleanup;
    }
    printf("[*] NtSetInformationThread was successful\n");

    //
    // -------------- End of Impersonation --------------
    //

    //
    // Get process token of current thread
    //

    if (!OpenThreadToken(hThread, TOKEN_ALL_ACCESS, TRUE, &hTokenThread))
    {
        printf("OpenThreadToken Failed (%d).\n", GetLastError());
        goto Cleanup;
    }
    printf("[*] OpenThreadToken was successful\n");
    if (!DuplicateTokenEx(hTokenThread, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &dupToken))
    {
        std::cout << "DuplicateTokenEx2 Failed (" << GetLastError() << ").\n";
        goto Cleanup;
    }
    printf("[*] DuplicateTokenEx2 was successful\n");
    ret = CreateProcessWithTokenW(dupToken, LOGON_WITH_PROFILE, NULL, process, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
    if (ret == FALSE)
    {
        printf("CreateProcessWithTokenW Failed (%d).\n", GetLastError());
        goto Cleanup;
    }
    printf("[*] CreateProcessWithTokenW was successful\n");

    ret = TRUE;

Cleanup:
    if (hToken)
    {
        CloseHandle(hToken);
    }
    if (dupToken)
    {
        CloseHandle(dupToken);
    }
    if (hThread)
    {
        CloseHandle(hThread);
    }
    if (hProcess)
    {
        CloseHandle(hProcess);
    }
    return ret;
}

BOOL ThreadImpersonation(DWORD ProcessId, DWORD ThreadId) {
    if (ThreadId == 0)
    {
        ThreadId = GetCurrentThreadId();
    }
    printf("[*] Changing the token of thread id %d\n", ThreadId);
    BOOL ret = FALSE;
    HANDLE hToken;
    HANDLE dupToken = NULL;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, ProcessId);
    if (hProcess == NULL)
    {
        printf("OpenProcess Failed (%d).\n", GetLastError());
        return -1;
    }
    printf("[*] OpenProcess was successful\n");
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken))
    {
        printf("OpenProcessToken Failed (%d).\n", GetLastError());
        return -1;
    }
    printf("[*] OpenProcessToken was successful\n");
    if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &dupToken))
    {
        std::cout << "DuplicateTokenEx Failed (" << GetLastError() << ").\n";
        return -1;
    }
    printf("[*] DuplicateTokenEx was successful\n");
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, ThreadId);
    if (hThread == NULL)
    {
        printf("OpenThread Failed (%d).\n", GetLastError());
        return -1;
    }
    printf("[*] OpenThread was successful\n");
    NTSTATUS status = NtSetInformationThread(hThread, ThreadImpersonationToken, &dupToken, sizeof(HANDLE));
    if (status != 0)
    {
        printf("NtSetInformationThread Failed (%d).\n", status);
        return -1;
    }
    printf("[*] NtSetInformationThread was successful\n");
    ret = TRUE;

Cleanup:
    if (hToken)
    {
        CloseHandle(hToken);
    }
    if (dupToken)
    {
        CloseHandle(dupToken);
    }
    if (hThread)
    {
        CloseHandle(hThread);
    }
    if (hProcess)
    {
        CloseHandle(hProcess);
    }
    return ret;
}

BOOL ImpersonateChangeTokenSessionId(DWORD ProcessId)
{
    printf("[*] Changing the token of thread id %d\n", GetCurrentThreadId());
    BOOL ret = FALSE;
    HANDLE hToken = NULL;
    HANDLE dupToken = NULL;
    HANDLE nToken = NULL;
    HANDLE impToken = NULL;
    HANDLE nProcessToken = NULL;
    HANDLE susToken = NULL;
    BOOL setSD;
    BOOL OpenToken;
    DWORD TokenSession = 0;
    STARTUPINFO si = { 0 };
    si.cb = sizeof STARTUPINFO;
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof PROCESS_INFORMATION);
    wchar_t process[] = L"C:\\Windows\\System32\\cmd.exe";

    //
    // -------------- Impersonation --------------
    //
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, ProcessId);
    if (hProcess == NULL)
    {
        printf("OpenProcess Failed (%d).\n", GetLastError());
        return -1;
    }
    printf("[*] OpenProcess was successful\n");
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken))
    {
        printf("OpenProcessToken Failed (%d).\n", GetLastError());
        return -1;
    }
    printf("[*] OpenProcessToken was successful\n");
    if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &dupToken))
    {
        std::cout << "DuplicateTokenEx Failed (" << GetLastError() << ").\n";
        return -1;
    }
    printf("[*] DuplicateTokenEx was successful\n");

    NTSTATUS status = NtSetInformationThread(GetCurrentThread(), ThreadImpersonationToken, &dupToken, sizeof(HANDLE));
    if (status != 0)
    {
        printf("NtSetInformationThread Failed (%d).\n", status);
        return -1;
    }
    printf("[*] NtSetInformationThread was successful\n");
    //
    // -------------- End of Impersonation --------------
    //

    //
    // Taking current thread's impersonation token and enabling SeAssignPrimaryTokenPrivilege
    //
    TOKEN_PRIVILEGES tpPrivilege;
    LUID Luid;
    if (!LookupPrivilegeValueW(NULL, L"SeAssignPrimaryTokenPrivilege", &Luid))
    {
        printf("LookupPrivilegeValueW Failed (%d).\n", GetLastError());
        return -1;
    }
    printf("[*] LookupPrivilegeValueW was successful\n");

    OpenToken = OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, TRUE, &impToken);
    if (OpenToken == NULL)
    {
        printf("OpenThreadToken Failed).\n");
    }
    tpPrivilege.PrivilegeCount = 1;
    tpPrivilege.Privileges[0].Luid = Luid;
    tpPrivilege.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(impToken, FALSE, &tpPrivilege, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
    {
        printf("AdjustTokenPrivileges Failed (%d).\n", GetLastError());
        return -1;
    }
    printf("[*] SeAssignPrimaryTokenPrivilege has been enabled\n");

    SECURITY_DESCRIPTOR sd;
    if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION))
    {
        printf("InitializeSecurityDescriptor Failed (%d).\n", GetLastError());
    }
    setSD = SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);
    if (!setSD)
    {
        printf("SetSecurityDescriptorDacl Failed (%d).\n", GetLastError());
    }

    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = &sd;
    sa.bInheritHandle = FALSE;

    //
   // Duplicating impersonation token to turn it to a primary token 
   //
    if (!DuplicateTokenEx(impToken, MAXIMUM_ALLOWED, &sa, SecurityAnonymous, TokenPrimary, &nToken)) {
        printf("DuplicateTokenEx failed (%d). \n", GetLastError());
        goto Cleanup;
    }
    printf("[*] DuplicateTokenEx was successful\n");

    if (!SetTokenInformation(nToken, TokenSessionId, &TokenSession, sizeof(TokenSession)))
    {
        printf("SetTokenInformation Failed (%d).\n", GetLastError());
        return -1;
    }
    printf("[*] SetTokenInformation was successful\n");

    //
    // Documenting the new primary token's session id
    //
    DWORD dwSessionId;
    DWORD dwReturnLength;
    if (!GetTokenInformation(nToken, TokenSessionId, &dwSessionId, sizeof(dwSessionId), &dwReturnLength)) {
        printf("GetTokenInformation failed (%d).\n", GetLastError());
        CloseHandle(nToken);
        return -1;
    }

    //
    // Creating a new process with the new primary token
    // 
    printf("[*] Creating process in a suspended state\n");
    if (!CreateProcess(process, 0, 0, FALSE, 0, CREATE_SUSPENDED | CREATE_NEW_CONSOLE, 0, 0, &si, &pi))
    {
        printf("CreateProcess Failed\n");
        goto Cleanup;
    }
    printf("[*] Process creation was successful\n");

    //
    // Getting a handle to the newly created process's default token
    //
    OpenProcessToken(pi.hProcess, TOKEN_ALL_ACCESS, &susToken);
    DWORD ncSessionId;
    DWORD ncReturnLength;

    if (!GetTokenInformation(susToken, TokenSessionId, &ncSessionId, sizeof(ncSessionId), &ncReturnLength)) {
        printf("GetTokenInformation 2 failed (%d).\n", GetLastError());
        CloseHandle(susToken);
        return -1;
    }

    printf("[*] New Process's Default Session ID: %u\n", ncSessionId);
    printf("[*] Desired Token's session ID: %u\n", dwSessionId);

    //
    // Call NtSetInformationProcess to set the desired access token with the changed session id
    //

    PROCESS_ACCESS_TOKEN ProcessAccessTokenStruct;

    ProcessAccessTokenStruct.Thread = NULL;
    ProcessAccessTokenStruct.Token = nToken;

    status = NtSetInformationProcess(pi.hProcess, ProcessAccessToken, &ProcessAccessTokenStruct, sizeof(PROCESS_ACCESS_TOKEN));
    if (status != 0) {
        printf("NtSetInformationProcess Failed (%d).\n", status);
        goto Cleanup;
    }
    printf("[*] NtSetInformationProcess was successful\n");

    ResumeThread(pi.hThread);
    printf("[*] Thread was resumed. Process should be running freely\n");

    //
    // Checking the process's access token to see if session id stuck
    //
    OpenProcessToken(pi.hProcess, TOKEN_ALL_ACCESS, &nProcessToken);
    if (nProcessToken == NULL)
    {
        printf("OpenProcessToken 2 Failed (%d).\n", status);
        goto Cleanup;
    }

    DWORD nSessionId;
    DWORD nReturnedLength;

    if (!GetTokenInformation(nProcessToken, TokenSessionId, &nSessionId, sizeof(nSessionId), &nReturnedLength)) {
        printf("GetTokenInformation failed (%d).\n", GetLastError());
        CloseHandle(nProcessToken);
        return -1;
    }

    printf("[*] Post-Assigned Token Session ID: %u\n", nSessionId);


    ret = TRUE;

Cleanup:
    if (hToken)
    {
        CloseHandle(hToken);
    }
    if (nToken)
    {
        CloseHandle(nToken);
    }
    if (dupToken)
    {
        CloseHandle(dupToken);
    }
    if (hProcess)
    {
        CloseHandle(hProcess);
    }
    if (pi.hProcess)
    {
        CloseHandle(pi.hProcess);
    }
    if (pi.hThread)
    {
        CloseHandle(pi.hThread);
    }
    if (nProcessToken)
    {
        CloseHandle(nProcessToken);
    }
    if (susToken)
    {
        CloseHandle(susToken);
    }
    if (impToken)
    {
        CloseHandle(impToken);
    }
    return ret;
}

BOOL ChangeTokenSessionId()
{
    BOOL ret = FALSE;
    BOOL setSD;
    HANDLE hToken = NULL;
    HANDLE nToken = NULL;
    HANDLE hThread = NULL;
    HANDLE nProcessToken = NULL;
    HANDLE susToken = NULL;
    HANDLE hProcess = NULL;
    NTSTATUS status;
    DWORD TokenSession = 2;
    STARTUPINFO si = { 0 };
    HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
    si.cb = sizeof STARTUPINFO;

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof PROCESS_INFORMATION);
    wchar_t process[] = L"C:\\Windows\\System32\\cmd.exe";

    //
    // Get process token of current process
    //
    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, &hToken);
    if (hToken == NULL) {
        goto Cleanup;
    }

    //
    // Updating privileges to enable SeAssignPrimaryTokenPrivilege
    //
    TOKEN_PRIVILEGES tpPrivilege;
    LUID Luid;
    if (!LookupPrivilegeValueW(NULL, L"SeAssignPrimaryTokenPrivilege", &Luid))
    {
        printf("LookupPrivilegeValueW Failed (%d).\n", GetLastError());
        return -1;
    }
    printf("[*] LookupPrivilegeValueW was successful\n");

    tpPrivilege.PrivilegeCount = 1;
    tpPrivilege.Privileges[0].Luid = Luid;
    tpPrivilege.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tpPrivilege, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
    {
        printf("AdjustTokenPrivileges Failed (%d).\n", GetLastError());
        return -1;
    }
    printf("[*] SeAssignPrimaryTokenPrivilege has been enabled\n");

    SECURITY_DESCRIPTOR sd;
    if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION))
    {
        printf("InitializeSecurityDescriptor Failed (%d).\n", GetLastError());
    }
    setSD = SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);
    if (!setSD)
    {
        printf("SetSecurityDescriptorDacl Failed (%d).\n", GetLastError());
    }

    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = &sd;
    sa.bInheritHandle = FALSE;

    //
    // Duplicate Token of current process and set it to a target process
    //
    if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, &sa, SecurityAnonymous, TokenPrimary, &nToken)) {
        printf("DuplicateTokenEx failed (%d). \n", GetLastError());
        goto Cleanup;
    }
    printf("[*] DuplicateTokenEx was successful\n");

    if (!SetTokenInformation(nToken, TokenSessionId, &TokenSession, sizeof(TokenSession)))
    {
        printf("SetTokenInformation Failed (%d).\n", GetLastError());
        return -1;
    }
    printf("[*] SetTokenInformation was successful\n");

    DWORD dwSessionId;
    DWORD dwReturnLength;

    if (!GetTokenInformation(nToken, TokenSessionId, &dwSessionId, sizeof(dwSessionId), &dwReturnLength)) {
        printf("GetTokenInformation failed (%d).\n", GetLastError());
        CloseHandle(nToken);
        return -1;
    }

    if (!CreateProcess(process, 0, 0, FALSE, 0, CREATE_SUSPENDED | CREATE_NEW_CONSOLE, 0, 0, &si, &pi))
    {
        printf("CreateProcess Failed\n");
        goto Cleanup;
    }
   // hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);

    //
   // Getting a handle to the newly created process's default token
   //
    OpenProcessToken(pi.hProcess, TOKEN_ALL_ACCESS, &susToken);
    DWORD ncSessionId;
    DWORD ncReturnLength;

    if (!GetTokenInformation(susToken, TokenSessionId, &ncSessionId, sizeof(ncSessionId), &ncReturnLength)) {
        printf("GetTokenInformation 2 failed (%d).\n", GetLastError());
        CloseHandle(susToken);
        return -1;
    }

    printf("[*] New Process's Default Session ID: %u\n", ncSessionId);
    printf("[*] Desired Token's session ID: %u\n", dwSessionId);

    //
    // Call NtSetInformationProcess to set the desired access token with the changed session id
    //
    PROCESS_ACCESS_TOKEN ProcessAccessTokenStruct;

    ProcessAccessTokenStruct.Thread = NULL;
    ProcessAccessTokenStruct.Token = nToken;

    status = NtSetInformationProcess(pi.hProcess, ProcessAccessToken, &ProcessAccessTokenStruct, sizeof(PROCESS_ACCESS_TOKEN));
    if (status != 0) {
        printf("NtSetInformationProcess Failed (%d).\n", status);
        goto Cleanup;
    }
    printf("[*] NtSetInformationProcess was successful\n");

    ResumeThread(pi.hThread);
    printf("[*] Process resumed\n");

    //
    // Checking the process's access token to see if session id stuck
    //
    OpenProcessToken(pi.hProcess, TOKEN_ALL_ACCESS, &nProcessToken);
    if (nProcessToken == NULL)
    {
        printf("OpenProcessToken 2 Failed (%d).\n", status);
        goto Cleanup;
    }

    DWORD nSessionId;
    DWORD nReturnedLength;
    

    if (!GetTokenInformation(nProcessToken, TokenSessionId, &nSessionId, sizeof(nSessionId), &nReturnedLength)) {
        printf("GetTokenInformation failed (%d).\n", GetLastError());
        CloseHandle(nProcessToken);
        return -1;
    }

    printf("[*] Post-Assigned Token Session ID: %u\n", nSessionId);

    ret = TRUE;

Cleanup:
    if (hToken)
    {
        CloseHandle(hToken);
    }
    if (nToken)
    {
        CloseHandle(nToken);
    }
    if (hThread)
    {
        CloseHandle(hThread);
    }
    if (hProcess)
    {
        CloseHandle(hProcess);
    }
    if (pi.hProcess)
    {
        CloseHandle(pi.hProcess);
    }
    if (pi.hThread)
    {
        CloseHandle(pi.hThread);
    }
    if (nProcessToken)
    {
        CloseHandle(nProcessToken);
    }
    if (susToken)
    {
        CloseHandle(susToken);
    }

    return ret;

}

int main(int argc, char* argv[])
{
    DWORD Option = atoi(argv[1]);
    if (Option != 2 && argc < 2)
    {
        printf("TokenActions.exe <Option - 1|2|3|4> <ProcessId> <ThreadId>\n");
        printf("Option 1 = ThreadImpersonation\n");
        printf("Option 2 = Assign Primary Token. TokenActions need to be running as SYSTEM\n");
        printf("Option 3 = ThreadImpersonation + CreateProcess\n");
        printf("Option 4 = ThreadImpersonation + Assign Primary Token - PID needs to be a SYSTEM PID like LSASS\n");
        return 0;
    }

    switch (Option)
    {
    case 1:
    {
        DWORD FirstProcessId = atoi(argv[2]);
        DWORD ThreadID = atoi(argv[3]);
        ThreadImpersonation(FirstProcessId, ThreadID);
        break;
    }
    case 2:
    {
        DWORD FirstProcessId = atoi(argv[2]);
        ChangeTokenSessionId();
        break;
    }
    case 3:
    {
        DWORD FirstProcessId = atoi(argv[2]);
        DWORD ThreadID = atoi(argv[3]);
        CreateProcessWithDuplication(FirstProcessId, ThreadID);
        break;
    }
    case 4:
    {
        DWORD FirstProcessId = atoi(argv[2]);
        ImpersonateChangeTokenSessionId(FirstProcessId);
        break;
    }
    default:
    {
        printf("Invalid Option\n");
        break;
    }
    }
    return 0;
}
