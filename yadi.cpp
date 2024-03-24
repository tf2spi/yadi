#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

static DWORD WINAPI itworks(void *unused)
{
	(void)unused;
	return 1337;
}

enum log_level
{
	LL_DEBUG = 0,
	LL_INFO = 1,
	LL_WARN = 2,
	LL_ERR = 3,
	LL_COUNT = 4,
};

#define LL_CURRENT LL_DEBUG

static void log(int level, const char *func, int line, const char *fmt, ...)
{
	const char *level_tags[LL_COUNT] =
	{
		"DEBUG",
		"INFO",
		"WARN",
		"ERR",
	};
	if (level < LL_CURRENT || level >= LL_COUNT)
		return;

	char tmp[256];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(tmp, sizeof(tmp), fmt, ap);
	va_end(ap);
	printf("[%s:%s:%d] %s\n", level_tags[level], func, line, tmp);
}

#define DEBUGF(...) log(LL_DEBUG, __FUNCTION__, __LINE__, __VA_ARGS__)
#define INFOF(...) log(LL_INFO, __FUNCTION__, __LINE__, __VA_ARGS__)
#define WARNF(...) log(LL_WARN, __FUNCTION__, __LINE__, __VA_ARGS__)
#define ERRF(...) log(LL_ERR, __FUNCTION__, __LINE__, __VA_ARGS__)

HMODULE LoadLibraryRemoteA(HANDLE hProcess, const char *lpLibName)
{
	HMODULE hModule = NULL;
	HANDLE hThread = NULL;
	HMODULE *lphModules = NULL;
	char *lpLibNameFull = NULL;
	size_t cbLibName = strlen(lpLibName) + 1;
	char *lpRemoteName = (char *)VirtualAllocEx(
		hProcess,
		NULL,
		cbLibName,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	);

	DWORD lpLibNameFullLen = GetFullPathNameA(
			lpLibName,
			0,
			NULL,
			NULL);
	lpLibNameFull = (char *)malloc(lpLibNameFullLen + 1);
	if (lpLibNameFull == NULL 
		|| !GetFullPathNameA(
			lpLibName,
			lpLibNameFullLen,
			lpLibNameFull,
			NULL))
	{
		ERRF("Failed to get full path of the library! %d",
				GetLastError());
		goto load_done;
	}

	if (lpRemoteName == NULL)
	{
		ERRF("Failed to allocate memory in remote process! %d",
				GetLastError());
		goto load_done;
	}
	if (!WriteProcessMemory(hProcess, lpRemoteName, lpLibName, cbLibName, NULL))
	{
		ERRF("Failed to write library name in remote process! %d",
				GetLastError());
		goto load_done;
	}

	hThread = CreateRemoteThread(
			hProcess,
			NULL,
			0,
			(LPTHREAD_START_ROUTINE)LoadLibraryA,
			lpRemoteName,
			0,
			NULL);
	if (hThread == NULL)
	{
		ERRF("Failed to create remote thread for LoadLibrary! %d",
				GetLastError());
		goto load_done;
	}
	INFOF("Waiting for remote thread to finish...");
	WaitForSingleObject(hThread, INFINITE);

	DWORD cbNeeded = 0;
	EnumProcessModules(hProcess, NULL, 0, &cbNeeded);
	lphModules = (HMODULE *)malloc(cbNeeded);
	if (lphModules == NULL || !EnumProcessModules(hProcess, lphModules, cbNeeded, &cbNeeded))
	{
		ERRF("Failed to enumerate all the process modules! %d",
				GetLastError());
		goto load_done;
	}

	DWORD dwModules = cbNeeded / sizeof(HMODULE);
	for (DWORD i = 0; i < dwModules; i++)
	{
		HMODULE hCurrentMod = lphModules[i];
		char szCurrentModName[MAX_PATH];
		if (!GetModuleFileNameExA(
			hProcess,
			hCurrentMod,
			szCurrentModName,
			sizeof(szCurrentModName)))
		{
			WARNF("Getting module %d failed! Continue...");
			continue;
		}
		if (!_stricmp(szCurrentModName, lpLibNameFull))
		{
			DEBUGF("Found module in target! %s %p",
					szCurrentModName, hCurrentMod);
			hModule = hCurrentMod;
			goto load_done;
		}
	}
	if (hModule == NULL)
	{
		ERRF("Failed to find injected library in target!");
		SetLastError(ERROR_NOT_FOUND);
		goto load_done;
	}

load_done:
	if (lpRemoteName != NULL)
		VirtualFreeEx(hProcess, lpRemoteName, 0, MEM_RELEASE);
	if (hThread != NULL)
		CloseHandle(hThread);
	if (lphModules != NULL)
		free(lphModules);
	if (lpLibNameFull != NULL)
		free(lpLibNameFull);

	return hModule;
}

static int injector_main(HANDLE hProcess, char **ppDllNames, int iDllCount)
{
	char szExeName[MAX_PATH];
	if (GetModuleFileNameA(NULL, szExeName, sizeof(szExeName))
			== sizeof(szExeName))
	{
		ERRF("Failed to get EXE module name! %d",
			GetLastError());
		return EXIT_FAILURE;
	}

	HMODULE hModuleExe = LoadLibraryRemoteA(hProcess, szExeName);
	if (hModuleExe == NULL)
	{
		ERRF("Failed to load ourselves remotely in process! %d",
			GetLastError());
		return EXIT_FAILURE;
	}
	DEBUGF("We did the thing! We loaded ourselves! %p",
		hModuleExe);

	DEBUGF("Confirming loading worked!");
	DWORD dwOffset = (ULONG_PTR)itworks - (ULONG_PTR)GetModuleHandle(NULL);
	LPTHREAD_START_ROUTINE itworks_ptr = (LPTHREAD_START_ROUTINE)
		((ULONG_PTR)hModuleExe + dwOffset);
	HANDLE hDumbThread = CreateRemoteThread(
			hProcess,
			NULL,
			0,
			itworks_ptr,
			NULL,
			0,
			NULL);
	if (hDumbThread != NULL)
	{
		WaitForSingleObject(hDumbThread, INFINITE);
		DWORD dwExitCode;
		if (GetExitCodeThread(hDumbThread, &dwExitCode))
		{
			DEBUGF("It worked: %u\n", dwExitCode);
		}
		else
		{
			ERRF("Failed to get its exit code :(. %d\n",
					GetLastError());
		}
	}
	else
	{
		ERRF("Failed to start thread testing itworks! %d",
				GetLastError());
	}

	for (int i = 0; i < iDllCount; i++)
	{
		const char *dllname = ppDllNames[i];
		DEBUGF("Injecting '%s'...", dllname);
		if (LoadLibraryRemoteA(hProcess, dllname) == NULL)
		{
			ERRF("Failed to load library! I dunno why!");
			continue;
		}
	}
	return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
	if (argc < 2)
	{
		fprintf(stderr, "Usage: %s [dlls*] cmdline\n", *argv);
		return EXIT_FAILURE;
	}
	char *lpCmdLine = argv[argc - 1];
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	DEBUGF("Starting with command '%s'!", lpCmdLine);
	if (!CreateProcess(NULL,
		lpCmdLine,
		NULL,
		NULL,
		FALSE,
		CREATE_SUSPENDED,
		NULL,
		NULL,
		&si,
		&pi))
	{
		ERRF("Failed to create process! %d", GetLastError());
		return EXIT_FAILURE;
	}

	int iExitCode = injector_main(pi.hProcess, &argv[1], argc - 2);
	ResumeThread(pi.hThread);

	// TODO: Don't wait for process to finish when building release
	//       Just use it for debug.
	DEBUGF("Waiting for process to finish...");
	WaitForSingleObject(pi.hProcess, INFINITE);
	return iExitCode;
}
