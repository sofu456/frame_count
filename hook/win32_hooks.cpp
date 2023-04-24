#include <iostream>
#include "windows.h"
using namespace std;

extern "C" __declspec(dllexport) void WINAPI SwapBuffers_hook(HDC hdc)
{
    cout << "hook ok" << endl;
}

void ApplyHooks(string module, string oldfunc, string newfunc)
{
    HMODULE hmod = GetModuleHandle(module.c_str());
    FARPROC* proc = (FARPROC*)&GetProcAddress(hmod,oldfunc.c_str());
    cout << module << ":" << hmod << "--"<< proc  << endl;
    HMODULE lmod = GetModuleHandle("hook_dll.dll");
    FARPROC nproc = GetProcAddress(lmod,newfunc.c_str());
    cout << "hook_dll.dll:"<< lmod << "--"<< nproc  << endl;
    *proc = nproc;
}
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if(ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        ApplyHooks("opengl32.dll","wglSwapBuffers","SwapBuffers_hook");
        ApplyHooks("Gdi32.dll","SwapBuffers","SwapBuffers_hook");
        return TRUE;
    }

    return TRUE;
}