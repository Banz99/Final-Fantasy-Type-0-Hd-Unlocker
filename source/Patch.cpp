#include "Utils/MemoryMgr.h"
#include "Utils/Patterns.h"

#include <Shlwapi.h>

#include <string_view>

#pragma comment(lib, "Shlwapi.lib")

wchar_t wcModulePath[MAX_PATH];
static HMODULE hDLLModule;


void OnInitializeHook()
{
	GetModuleFileNameW(hDLLModule, wcModulePath, _countof(wcModulePath) - 3); // Minus max required space for extension
	PathRenameExtensionW(wcModulePath, L".ini");

	using namespace Memory::VP;
	using namespace hook;
	
	const int ResX = GetPrivateProfileIntW(L"OverrideRes", L"ResX", 0, wcModulePath);
	const int ResY = GetPrivateProfileIntW(L"OverrideRes", L"ResY", 0, wcModulePath);

	if (ResX > 0 && ResY > 0)
	{
		auto switchToLive = pattern("C4 40 5F C3 C7 07 80 07 00 00 C7 03 38 04 00 00").count(1); 
		if (switchToLive.size() == 1)
		{
			Patch<int32_t>(switchToLive.get_first<void>(0x6), ResX);
			Patch<int32_t>(switchToLive.get_first<void>(0xC), ResY);
		}

		switchToLive = pattern("75 21 41 0B C4 B9 80 07 00 00 BA 38 04 00 00").count(1);

		if (switchToLive.size() == 1)
		{
			Patch<int32_t>(switchToLive.get_first<void>(0x6), ResX);
			Patch<int32_t>(switchToLive.get_first<void>(0xB), ResY);
		}
	}
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	UNREFERENCED_PARAMETER(lpvReserved);

	if ( fdwReason == DLL_PROCESS_ATTACH )
	{
		hDLLModule = hinstDLL;
	}
	return TRUE;
}