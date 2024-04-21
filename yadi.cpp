#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>

struct ImageBase {};
#ifdef __cplusplus
extern "C" struct ImageBase __ImageBase;
#else
extern struct ImageBase __ImageBase;
#endif

// Target Begin
struct TargetTable
{
	HMODULE (WINAPI *lpLoadLibraryA)(LPCSTR);
	BOOL (WINAPI *lpFreeLibrary)(HMODULE);
	DWORD (WINAPI *lpGetLastError)(void);
	HMODULE *lpModules;
};
static struct TargetTable target;

DWORD TargetMain(const char **argv)
{
	for (int i = 0; argv[i] != NULL; i++)
	{
		const char *dll = argv[i];
		HMODULE hLib = target.lpLoadLibraryA(dll);

		// If preloading a library fails, DO NOT unload other libraries
		if (hLib == NULL)
		{
			return ~i;
		}
		// TODO: If a DLL fails to get injected, it should be cleaned up to avoid leaks on attach
	}
	return 0;
}
// Target End

// Injector Begin
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

static BOOL ProcessRPC(HANDLE hProcess, LPTHREAD_START_ROUTINE routine, LPVOID data, DWORD *pdwExitCode)
{
	HANDLE hThread = CreateRemoteThread(
		hProcess,
		NULL,
		0,
		routine,
		data,
		0,
		NULL);
	if (hThread == NULL)
	{
		ERRF("Failed to create remote thread for calling function %p! %d",
				GetLastError());
		return FALSE;
	}
	WaitForSingleObject(hThread, INFINITE);
	BOOL success = TRUE;
	if (pdwExitCode != NULL)
	{
		success = GetExitCodeThread(hThread, pdwExitCode);
	}
	CloseHandle(hThread);
	return success;
}

HMODULE LoadLibraryRemoteA(HANDLE hProcess, const char *lpLibName, HMODULE **ppModules, DWORD *pdwModules)
{
	HMODULE hModule = NULL;

	DWORD lpLibNameFullLen = GetFullPathNameA(
			lpLibName,
			0,
			NULL,
			NULL);
	char *lpLibNameFull = (char *)malloc(lpLibNameFullLen + 1);
	if (lpLibNameFull == NULL 
		|| !GetFullPathNameA(
			lpLibName,
			lpLibNameFullLen,
			lpLibNameFull,
			NULL))
	{
		ERRF("Failed to get full path of the library! %d",
				GetLastError());
		goto getfullpath_failed;
	}

	char *lpRemoteName = (char *)VirtualAllocEx(
		hProcess,
		NULL,
		lpLibNameFullLen + 1,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	);
	if (lpRemoteName == NULL)
	{
		ERRF("Failed to allocate memory in remote process! %d",
				GetLastError());
		goto vallocex_failed;
	}

	if (!WriteProcessMemory(hProcess, lpRemoteName, lpLibName, lpLibNameFullLen + 1, NULL))
	{
		ERRF("Failed to write library name in remote process! %d",
				GetLastError());
		goto loadlibrary_failed;
	}

	if (!ProcessRPC(hProcess, (LPTHREAD_START_ROUTINE)LoadLibraryA, lpRemoteName, NULL))
	{
		ERRF("RPC call to LoadLibrary failed!\n");
		goto loadlibrary_failed;
	}

	DWORD cbNeeded = 0;
	EnumProcessModules(hProcess, NULL, 0, &cbNeeded);
	HMODULE *lphModules = (HMODULE *)malloc(cbNeeded);
	if (lphModules == NULL || !EnumProcessModules(hProcess, lphModules, cbNeeded, &cbNeeded))
	{
		ERRF("Failed to enumerate all the process modules! %d",
				GetLastError());
		goto enummodules_failed;
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
			break;
		}
	}

	if (hModule == NULL)
	{
		ERRF("Failed to find injected library in target!");
		SetLastError(ERROR_NOT_FOUND);
	}
	else if (ppModules != NULL && pdwModules != NULL)
	{
		*pdwModules = dwModules;
		*ppModules = lphModules;
		dwModules = 0;
		lphModules = NULL;
	}

enummodules_failed:
	free(lphModules);
loadlibrary_failed:
	VirtualFreeEx(hProcess, lpRemoteName, 0, MEM_RELEASE);
vallocex_failed:
getfullpath_failed:
	free(lpLibNameFull);
	return hModule;
}

static LPCVOID TargetTranslate(HMODULE hSelfRemote, LPCVOID pSelfVA)
{
	return (LPCVOID)((uintptr_t)hSelfRemote - (uintptr_t)&__ImageBase + (uintptr_t)pSelfVA);
}

static BOOL TargetInit(HANDLE hProcess, HMODULE hSelfRemote, HMODULE *lpModules, DWORD dwModules)
{
	target.lpLoadLibraryA = LoadLibraryA;
	target.lpFreeLibrary = FreeLibrary;
	target.lpGetLastError = GetLastError;

	assert(SIZE_MAX / sizeof(*lpModules) >= dwModules);
	size_t cbModules = sizeof(*lpModules) * dwModules;
	LPVOID lpModulesRemote = VirtualAllocEx(
			hProcess,
			NULL,
			cbModules,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_READWRITE);
	if (lpModulesRemote == NULL)
	{
		ERRF("Failed to allocate memory for storing modules on target! %d",
				GetLastError());
		return FALSE;
	}
	target.lpModules = (HMODULE *)lpModulesRemote;

	struct TargetTable *lpTargetRemote = (struct TargetTable *)TargetTranslate(hSelfRemote, &target);
	if (!WriteProcessMemory(hProcess, lpModulesRemote, lpModules, cbModules, NULL)
		|| !WriteProcessMemory(hProcess, lpTargetRemote, &target, sizeof(target), NULL))
	{
		ERRF("Failed to write to remote target! %d",
				GetLastError());
		VirtualFreeEx(hProcess, lpModulesRemote, 0, MEM_RELEASE);
		target.lpModules = NULL;
		return FALSE;
	}
	DEBUGF("Target initialized!");
	return TRUE;
}

static const char **CreateRemoteArgv(HANDLE hProcess, int argc, const char **argv)
{
	assert(argc >= 0 && ((SIZE_MAX / sizeof(*argv)) - 1u) >= (size_t)argc);

	size_t cbNeeded = sizeof(*argv) * (argc + 1);
	size_t iArgvStart = cbNeeded;
	for (int i = 0; i < argc; i++)
	{
		size_t slen = strlen(argv[i]);
		assert(SIZE_MAX - slen > cbNeeded);
		cbNeeded += (slen + 1);
	}

	char **tmp = (char **)malloc(cbNeeded);
	if (tmp == NULL)
	{
		ERRF("Failed to allocate memory for local argv!\n");
		return NULL;
	}
	tmp[argc] = NULL;
	char *iter = (char *)tmp + iArgvStart;
	for (int i = 0; i < argc; i++)
	{
		const char *arg = argv[i];
		size_t len = strlen(arg) + 1;
		memcpy(iter, arg, len);
		tmp[i] = iter;
		iter += len;
	}

	LPVOID lpRemote = VirtualAllocEx(
		hProcess,
		NULL,
		cbNeeded,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	);
	if (lpRemote == NULL)
	{
		free(tmp);
		ERRF("Failed to allocate memory for remote argv! %d\n");
		return NULL;
	}
	for (int i = 0; i < argc; i++)
	{
		tmp[i] += ((uintptr_t)lpRemote - (uintptr_t)tmp);
	}

	BOOL success = WriteProcessMemory(hProcess, lpRemote, tmp, cbNeeded, NULL);
	free(tmp);
	tmp = NULL;
	cbNeeded = 0;
	if (!success)
	{
		VirtualFreeEx(hProcess, lpRemote, 0, MEM_RELEASE);
		ERRF("Failed to write local argv to remote argv! %d",
				GetLastError());
		return NULL;
	}

	return (const char **)lpRemote;
}

// This function should always clean up any remote resources
// it allocates so that the other process can have as much
// memory as possible after the injection.
static int InjectorMain(HANDLE hProcess, char **ppDllNames, int iDllCount)
{
	char szExeName[MAX_PATH];
	if (GetModuleFileNameA(NULL, szExeName, sizeof(szExeName))
			== sizeof(szExeName))
	{
		ERRF("Failed to get EXE module name! %d",
			GetLastError());
		return EXIT_FAILURE;
	}

	HMODULE *lpModulesRemote;
	DWORD dwModules;
	HMODULE hModuleExe = LoadLibraryRemoteA(hProcess, szExeName, &lpModulesRemote, &dwModules);
	if (hModuleExe == NULL)
	{
		ERRF("Failed to load ourselves remotely in process! %d",
			GetLastError());
		return EXIT_FAILURE;
	}
	DEBUGF("We did the thing! We loaded ourselves! Local:%p Remote:%p",
		&__ImageBase, hModuleExe);

	BOOL success = TargetInit(hProcess, hModuleExe, lpModulesRemote, dwModules);
	free(lpModulesRemote);
	lpModulesRemote = NULL;
	dwModules = 0;
	DWORD iExitCode = EXIT_FAILURE;
	if (success)
	{
		const char **ppRemoteArgv = CreateRemoteArgv(hProcess, iDllCount, (const char **)ppDllNames);
		if (ppRemoteArgv != NULL)
		{
			ppDllNames[iDllCount] = NULL;
			if (!ProcessRPC(hProcess,
				(LPTHREAD_START_ROUTINE)TargetTranslate(hModuleExe, TargetMain),
				ppRemoteArgv,
				&iExitCode))
			{
				iExitCode = EXIT_FAILURE;
			}
			VirtualFreeEx(hProcess, ppRemoteArgv, 0, MEM_RELEASE);
		}
		VirtualFreeEx(hProcess, target.lpModules, 0, MEM_RELEASE);
	}
	else
	{
		ERRF("But in the end, it doesn't even matter!");
	}
	if (!ProcessRPC(hProcess, (LPTHREAD_START_ROUTINE)FreeLibrary, hModuleExe, NULL))
	{
		WARNF("RPC call to FreeLibrary failed? Strange but not fatal!");
	}
	return (int)iExitCode;
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

	// TODO: Consider detecting if a process ID is given or not
	//       and give the user the option to attach to a process
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

	int iExitCode = InjectorMain(pi.hProcess, &argv[1], argc - 2);
	if (iExitCode != EXIT_SUCCESS)
	{
		// TODO: On failure, if we attach to a process,
		//       we should not terminate it.
		ERRF("Injection was unsuccessful! :(");
		TerminateProcess(pi.hProcess, iExitCode);
		return iExitCode;
	}
	INFOF("Injection successful! Yaaaaaaaaaaaaaaay!");
	ResumeThread(pi.hThread);

	// TODO: Don't wait for process to finish when building release
	//       Just use it for debug.
	DEBUGF("Waiting for process to finish...");
	WaitForSingleObject(pi.hProcess, INFINITE);
	return iExitCode;
}
// Injector End
