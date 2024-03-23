#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

BOOL WINAPI DllMain(
	HINSTANCE hinstDLL,
	DWORD fdwReason,
	LPVOID lpvReserved)
{
	HMODULE hMods[512];
	DWORD cbNeeded;
	switch (fdwReason)
	{
		case DLL_PROCESS_ATTACH:
			if (EnumProcessModules(GetCurrentProcess(), hMods, sizeof(hMods), &cbNeeded))
			{
				for (int i = 0; i < cbNeeded / sizeof(*hMods); i++)
				{
					char name[260];
					if (GetModuleFileNameA(hMods[i], name, sizeof(name)))
					{
						fprintf(stderr, "Mod name: %s\n", name);
					}
				}
			}
			break;
	}
	return TRUE;
}
