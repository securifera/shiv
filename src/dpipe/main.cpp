#include <windows.h>
#include "npsvr.h"

/*
 * Current DLL hmodule.
 */
static HMODULE dll_handle = NULL;

extern "C" __declspec (dllexport) void __stdcall StartComponent(){
	npsrv_entry();
}

extern "C" __declspec (dllexport) void __stdcall StopComponent() {
	npsrv_exit();
}

extern "C" __declspec (dllexport) void __stdcall OnSessionChange() {
	//system("echo change >> C:\\o.txt");
}

extern "C" __declspec (dllexport) void __stdcall Refresh() {
	//npsrv_entry();
}

//===============================================================================================//
BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved )
{
	BOOL bReturnValue = TRUE;

	switch( dwReason ) 
    { 
		case DLL_PROCESS_ATTACH:
			dll_handle = (HMODULE)hinstDLL;
		case DLL_PROCESS_DETACH:
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
            break;
    }
	return bReturnValue;
}
