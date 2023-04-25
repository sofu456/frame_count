#include <iostream>
#include <algorithm>
#include <sstream>
#include "windows.h"
#include <imagehlp.h>
#include "tlhelp32.h"
using namespace std;

extern "C" __declspec(dllexport) void WINAPI SwapBuffers_hook(HDC hdc)
{
    stringstream ss;
    static _int64 tk=0;
    ss << "fps "<< 1000.0/(GetTickCount64()-tk) <<"/s\0";
    TextOut(hdc, 0, 0, ss.str().c_str(), 14);
    SwapBuffers(hdc);
    tk = GetTickCount64();
}

void ApplyHooks(string module, string oldfunc, string newfunc)
{
    ULONG uSize = 0;
    HMODULE hbase = GetModuleHandle(NULL);
    HMODULE hmod = GetModuleHandle(module.c_str());
    FARPROC proc = GetProcAddress(hmod,oldfunc.c_str());
    cout << module << ":" << hmod << "--" << proc  << endl;
    HMODULE lmod = GetModuleHandle("hook_dll.dll");
    FARPROC nproc = GetProcAddress(lmod,newfunc.c_str());
    cout << "hook_dll.dll:"<< lmod << "--"<< nproc  << endl;

    PIMAGE_IMPORT_DESCRIPTOR pImportDesc=(PIMAGE_IMPORT_DESCRIPTOR)
        ImageDirectoryEntryToData(hbase, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &uSize);
    for (;pImportDesc->Name;pImportDesc++){
        string sz_module = (char*)((char*)hbase+pImportDesc->Name);
        transform(sz_module.begin(),sz_module.end(),sz_module.begin(),tolower);
        if(sz_module==module) break;
    }
    PIMAGE_THUNK_DATA32 pThunk=(PIMAGE_THUNK_DATA32)((char*)hbase+pImportDesc->FirstThunk);
    for (; pThunk->u1.Function; pThunk++){
        if (pThunk->u1.Function == (DWORD)proc){
            DWORD dwOldProtect;
            if (VirtualProtect(&pThunk->u1.Function, 4096, PAGE_READWRITE, &dwOldProtect)){
                cout << "correct address success"<<endl;
                pThunk->u1.Function = (DWORD)nproc;
                break;
            }
        }
    }
}
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if(ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        //ApplyHooks("opengl32.dll","wglSwapBuffers","SwapBuffers_hook");
        ApplyHooks("gdi32.dll","SwapBuffers","SwapBuffers_hook");
        return TRUE;
    }

    return TRUE;
}