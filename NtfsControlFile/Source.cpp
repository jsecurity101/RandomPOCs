/* Author: Jonathan Johnson (@jsecurity101)
* Execute: NtfsControlFile.exe then connect to named pipe \\pipe\npfs
*/

#include <Windows.h>
#include <iostream>
#include <Lmcons.h>
#include <fstream>
#include <sddl.h>


#define FSCTL_PIPE_IMPERSONATE CTL_CODE(FILE_DEVICE_NAMED_PIPE, 7, METHOD_BUFFERED, FILE_ANY_ACCESS)


#define BUFSIZE 2048
#define INSTANCES 4 

typedef struct
{
	OVERLAPPED oOverlap;
	HANDLE hPipeInst;
	TCHAR chRequest[BUFSIZE];
	DWORD cbRead;
	TCHAR chReply[BUFSIZE];
	DWORD cbToWrite;
	DWORD dwState;
	BOOL fPendingIO;
} PIPEINST, * LPPIPEINST;


typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef enum _EVENT_TYPE {
	NotificationEvent,
	SynchronizationEvent
} EVENT_TYPE;

typedef VOID(*PIO_APC_ROUTINE)(
	__in PVOID ApcContext,
	__in PIO_STATUS_BLOCK IoStatusBlock,
	__in ULONG Reserved
	);

typedef NTSTATUS(*_NtFsControlFile)(
	HANDLE FileHandle,
	HANDLE Event,
	PIO_APC_ROUTINE ApcRoutine,
	PVOID ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	ULONG FsControlCode,
	PVOID InputBuffer,
	ULONG InputBufferLength,
	PVOID OutputBuffer,
	ULONG OutputBufferLength
	);

int main() {
	HANDLE hPipe = NULL;
	DWORD i, dwRead;
	TCHAR chBuf[BUFSIZE];
	TCHAR username[UNLEN + 1];
	DWORD username_len = UNLEN + 1;
	if (!GetUserName(username, &username_len))
	{
		printf("GetUserName Failed (%d).\n", GetLastError());
		DisconnectNamedPipe(hPipe);
		CloseHandle(hPipe);
		return 1;
	}
	else
	{
		std::wstring username_w(username);
		std::string username_s(username_w.begin(), username_w.end());
		std::cout << "[*] Current username is: " << username_s << "\n";
	}
	printf("[*] Creating named pipe npfs...\n");
	hPipe = CreateNamedPipe(L"\\\\.\\pipe\\npfs", PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, PIPE_TYPE_BYTE | PIPE_WAIT, 10, 2048, 2048, 0, NULL);

	if (hPipe == INVALID_HANDLE_VALUE)
	{
		printf("[-] CreateNamedPipe failed: (%d).\n", GetLastError());
		return 1;
	}
	else
	{
		printf("[*] Named pipe created!\n");
		printf("[*] Waiting for client to connect...\n");

		if (!ConnectNamedPipe(hPipe, NULL)) {
			printf("[-] ConnectNamedPipe failed: (%d).\n", GetLastError());
			CloseHandle(hPipe);
			return 1;
		}
		else {
			printf("[*] Client connected to named pipe!\n");
			if (!ReadFile(hPipe, chBuf, BUFSIZE * sizeof(TCHAR), &dwRead, NULL)) {
				printf("[-] ReadFile failed: (%d).\n", GetLastError());
				DisconnectNamedPipe(hPipe);
				CloseHandle(hPipe);
				return 1;
			}
			else {
				printf("[*] ReadFile completed!\n");
				_NtFsControlFile NtFsControlFile = (_NtFsControlFile)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtFsControlFile");
				if (NtFsControlFile == NULL) {
					printf("[-] NtFsControlFile not found!\n");
					DisconnectNamedPipe(hPipe);
					CloseHandle(hPipe);
					return 1;
				}
				else {
					printf("[*] NtFsControlFile found!\n");
				}
				

				IO_STATUS_BLOCK ioStatusBlock;
				NTSTATUS status = NtFsControlFile(hPipe, NULL, NULL, NULL, &ioStatusBlock, FSCTL_PIPE_IMPERSONATE, NULL, 0, NULL, 0);
				if (status != 259) {
					printf("[-] NtFsControlFile failed: (%d).\n", GetLastError());
					DisconnectNamedPipe(hPipe);
					CloseHandle(hPipe);
					return 1;

				}
				else {
					WaitForSingleObject(hPipe, INFINITE);
					printf("[*] NtFsControlFile completed!\n");
					if (!GetUserName(username, &username_len))
					{
						printf("GetUserName Failed (%d).\n", GetLastError());
						DisconnectNamedPipe(hPipe);
						CloseHandle(hPipe);
						return 1;
					}
					else
					{
						std::wstring username_w(username);
						std::string username_s(username_w.begin(), username_w.end());
						printf("[*] Current username is: %s\n", username_s.c_str());
					}
				}

			}
		}
		DisconnectNamedPipe(hPipe);
		CloseHandle(hPipe);
	}

	return 0;
}