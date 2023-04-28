#include <iostream>
#include <algorithm>
#include <functional>
#include <list>
#include <sstream>
#include "windows.h"
#include <imagehlp.h>
#include "tlhelp32.h"
using namespace std;

#include "marco_define.h"

extern "C" __declspec(dllexport) BOOL BitBlt_hook(HDC hdc,int x,int y,int cx,int cy,HDC hdcSrc,int x1,int y1,DWORD rop)
{
    stringstream ss;
    static _int64 tk=0, count = 0;
    ss << "gdi fps:"<< 1000.0/(GetTickCount64()-tk) <<"/s, all frame count:"<<(++count);
    TextOut(hdc, 0, 0, ss.str().c_str(), ss.str().size());
    BitBlt(hdc,x,y,cx,cy,hdcSrc,x1,y1,rop);
    tk = GetTickCount64();
    return true;
}
extern "C" __declspec(dllexport) void SwapBuffers_hook(HDC hdc)
{
    stringstream ss;
    static _int64 tk=0, count = 0;
    ss << "opengl fps:"<< 1000.0/(GetTickCount64()-tk) <<"/s, all frame count:"<<(++count);
    cout << ss.str() << endl;
    TextOut(hdc, 0, 0, ss.str().c_str(), ss.str().size());
    SwapBuffers(hdc);
    tk = GetTickCount64();
}
extern "C" __declspec(dllexport) void Message(const char* text)
{
    MessageBox(0,text,"tips",0);
}
// auto hook_all(...)                                                              
// {                                                                           
//     auto it = find_if(func_hooks.begin(),func_hooks.end(),[](auto& o){      
//         return (FARPROC)o.pNewfunc==(FARPROC)&hook_all;}                        
//     );                                                                      
//     if(it!=func_hooks.end()){                                               
//         cout << "--enter function " <<it->sz_func<<endl;                    
//         auto ret = ((auto (*)(...))it->pOldfunc)(__VA_ARGS__);                                          
//         cout << "##out function " <<it->sz_func<<endl;
//         return ret;                 
//     }
//     return false;                                                             
// }
// void SetIATHook(HMODULE hbase,string module,LPVOID pOldFuncAddr, LPVOID pNewFuncAddr)
// {
//     IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)hbase;
//     IMAGE_OPTIONAL_HEADER* pOpNtHeader = (IMAGE_OPTIONAL_HEADER*)((BYTE*)hbase + pDosHeader->e_lfanew + 24);
//     IMAGE_IMPORT_DESCRIPTOR* pImportDesc = (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)hbase + pOpNtHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
//     for (;pImportDesc->Name;pImportDesc++){
//         string sz_module = (char*)((char*)hbase+pImportDesc->Name);
//         transform(sz_module.begin(),sz_module.end(),sz_module.begin(),tolower);
//         if(sz_module==module) break;
//     }
// 	for (;pImportDesc->OriginalFirstThunk || pImportDesc->FirstThunk;pImportDesc++)
// 	{
// 		PIMAGE_THUNK_DATA32 pThunkData = (PIMAGE_THUNK_DATA32)((char*)hbase + pImportDesc->FirstThunk);
// 		for (;*((PDWORD)pThunkData) != 0;pThunkData++){
// 			if (*(PDWORD)pThunkData == (DWORD)pOldFuncAddr){
// 				*(PDWORD)pThunkData = (DWORD)pNewFuncAddr;
// 				return;
// 			}
// 		}
// 	}
// }
void SetIATHook(HMODULE hbase,string module,FARPROC proc,FARPROC nproc)
{
    ULONG uSize = 0;
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
            if (VirtualProtect(&pThunk->u1.Function, 0x1000, PAGE_READWRITE, &dwOldProtect)){
                cout << "correct address success"<<endl;
                pThunk->u1.Function = (DWORD)nproc;
                break;
            }
        }
    }
}
void HookFunc(string module, string oldfunc, string newfunc)
{
    HMODULE hbase = GetModuleHandle(NULL);
    HMODULE hmod = GetModuleHandle(module.c_str());
    FARPROC proc = GetProcAddress(hmod,oldfunc.c_str());
    cout << module << ":" << hmod << "--" << proc  << endl;
    HMODULE lmod = GetModuleHandle("hook_dll.dll");
    FARPROC nproc = GetProcAddress(lmod,newfunc.c_str());
    //FARPROC nproc = (FARPROC)&SwapBuffers_hook;
    cout << "hook_dll.dll:"<< lmod << "--"<< nproc  << endl;
    SetIATHook(hbase,module,proc,nproc);
}
void HookFunc(string module, string oldfunc, FARPROC newfunc)
{
    HMODULE hbase = GetModuleHandle(NULL);
    HMODULE hmod = GetModuleHandle(module.c_str());
    FARPROC proc = GetProcAddress(hmod,oldfunc.c_str());
    cout << module << ":" << hmod << "--" << proc  << endl;
    HMODULE lmod = GetModuleHandle("hook_dll.dll");
    cout << "hook_dll.dll:"<< lmod << "--"<< newfunc  << endl;
    SetIATHook(hbase,module,proc,newfunc);
}
void HookAllModuleFunc(string module)
{
    HMODULE hbase = GetModuleHandle(module.c_str());
    PIMAGE_DOS_HEADER MZ = (PIMAGE_DOS_HEADER)hbase;
	PIMAGE_NT_HEADERS PE = (PIMAGE_NT_HEADERS)((LPBYTE)MZ + MZ->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY pExportDesc = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)hbase + PE->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    for (int i=0;i<pExportDesc->NumberOfNames;i++){
        DWORD* parray = (DWORD*)((char*)hbase+pExportDesc->AddressOfNames);
        string sz_func = (char*)hbase+parray[i];
        cout<<i<<"----hook "<<sz_func<<":"<<"--"<<func_ptr[i]<<endl;
        FARPROC proc = GetProcAddress(hbase,sz_func.c_str());

        FuncWrap fw;
        fw.sz_func = sz_func;
        fw.pOldfunc = (void (*)(...))proc;
        fw.pNewfunc = func_ptr[i];
        func_hooks.emplace_back(fw);
        HookFunc(module, sz_func.c_str(), (FARPROC)func_hooks.back().pNewfunc);
    }
}
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if(ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        //HookAllModuleFunc("gdi32.dll");
        //HookFunc("opengl32.dll","wglSwapBuffers","SwapBuffers_hook");
        HookFunc("gdi32.dll","SwapBuffers","SwapBuffers_hook");
        HookFunc("gdi32.dll","BitBlt","BitBlt_hook");

        // auto pfunc = [](HDC hdc){cout<<"hook ok"<<endl;};
        // HookFunc("gdi32.dll", "SwapBuffers", (FARPROC)(void (*)(HDC))pfunc);
        return TRUE;
    }

    return TRUE;
}