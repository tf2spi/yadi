#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

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

BOOL LoadLibraryRemoteA(HANDLE hProcess, const char *lpLibName)
{
	BOOL success = FALSE;
	size_t cbLibName = strlen(lpLibName) + 1;
	char *lpRemoteName = (char *)VirtualAllocEx(
		hProcess,
		NULL,
		cbLibName,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	);
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
	HANDLE hThread = CreateRemoteThread(
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
	DWORD dwExitCode = 0;
	if (GetExitCodeThread(hThread, &dwExitCode))
	{
		DEBUGF("RemoteLoadLibrary thread exited with code %d", dwExitCode);
	}
	else
	{
		WARNF("Could not get exit code of thread in RemoteLoadLibrary? %d",
				GetLastError());
	}
	success = (dwExitCode != 0);
	if (!success)
	{
		ERRF("LoadLibraryA failed (for some reason...)");
	}
load_done:
	if (lpRemoteName != NULL)
		VirtualFreeEx(hProcess, lpRemoteName, 0, MEM_RELEASE);
	if (hThread != NULL)
		CloseHandle(hThread);
	return success;
}

int main(int argc, char **argv)
{
	if (argc < 2)
	{
		fprintf(stderr, "Usage: %s [dlls*] cmdline\n", *argv);
		return 1;
	}
	char *cmdline = argv[argc - 1];
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	DEBUGF("Starting with command '%s'!", cmdline);
	if (!CreateProcess(NULL,
		cmdline,
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
		return 1;
	}
	for (int i = 1; i < argc - 1; i++)
	{
		const char *dllname = argv[i];
		DEBUGF("Injecting '%s'...", dllname);
		if (!LoadLibraryRemoteA(pi.hProcess, dllname))
		{
			ERRF("Failed to load library! I dunno why!");
			TerminateProcess(pi.hProcess, 1337);
			break;
		}
	}

	DEBUGF("Waiting for process to finish...");
	ResumeThread(pi.hThread);
	WaitForSingleObject(pi.hProcess, INFINITE);
	return 0;
}
