#include <iostream>
#include <string>
#include <thread>
#include <signal.h>
#include <boost/process.hpp>
#include <boost/filesystem.hpp>
using namespace std;

#define HOOK_DLL "hook_dll.dll"

#if WIN32
#include "winuser.h"
#include "tlhelp32.h"
void callfunc(string dllpath,boost::process::child& child, string func,string data)
{
    __int64 pid = (__int64)child.id();
    HMODULE hmod = LoadLibrary(dllpath.c_str());
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if(!hProcess) {
        cout << "open process fail" <<endl;
        return;
    }
    HMODULE hkdll = GetModuleHandleA(HOOK_DLL);
    // HANDLE hkremote = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    // MODULEENTRY32 me32={};
    // me32.dwSize = sizeof(MODULEENTRY32);
    // BOOL success =Module32First(hkremote, &me32);
    // if(success == FALSE) CloseHandle(hkremote);

    // uintptr_t hbase=0;
    // do{
    //     if(strcmp(me32.szModule,HOOK_DLL)==0)
    //         hbase=(uintptr_t)me32.modBaseAddr;
    // }while(Module32Next(hkremote,&me32));
    uintptr_t func_local = (uintptr_t)GetProcAddress(hkdll, func.c_str());
    uintptr_t func_remote = func_local;//+hbase-(uintptr_t)hkdll;    //not kernel library
    FreeLibrary(hmod);

    void *remoteMem = VirtualAllocEx(hProcess, NULL, data.size(), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    SIZE_T numWritten=0;
    WriteProcessMemory(hProcess, remoteMem, data.c_str(), data.size(), &numWritten);

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)func_remote, remoteMem, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);
    //ReadProcessMemory(hProcess, remoteMem,  (void*)data.c_str(), data.size(), &numWritten);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
}
void inject(string filepath, boost::process::child& child)
{
    __int64 pid = (__int64)child.id();
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if(!hProc) {
        cout << "open process fail" <<endl;
        return;
    }
	LPVOID lpAddr =  VirtualAllocEx(hProc,NULL, filepath.size(), MEM_COMMIT, PAGE_READWRITE);
    if(!lpAddr) {
        CloseHandle(hProc);
        cout << "alloc memory fail"<<endl;
        return;
    }
	WriteProcessMemory(hProc, lpAddr, filepath.c_str(), filepath.size(), NULL);
	HMODULE sysMod = LoadLibraryA("Kernel32.dll");
    if(!sysMod){
        VirtualFreeEx(hProc, lpAddr, 0, MEM_RELEASE);
        CloseHandle(hProc);
        cout << "load kernel dll fail"<<endl;
        return;
    }
	LPTHREAD_START_ROUTINE fp =(LPTHREAD_START_ROUTINE) GetProcAddress(sysMod, "LoadLibraryA");
	HANDLE hThread = CreateRemoteThread(hProc, NULL, NULL,(LPTHREAD_START_ROUTINE)fp, lpAddr, 0, NULL);
    if(!hThread) {
        VirtualFreeEx(hProc, lpAddr, 0, MEM_RELEASE);
        CloseHandle(hProc);
        cout << "create remote thread fail"<<endl;
        return;
    }
    WaitForSingleObject(hThread, INFINITE);

    VirtualFreeEx(hProc, lpAddr, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProc);
}
#endif

boost::process::child child;
int main(int argc, char* argv[])
{
    boost::process::ipstream out_stream;
#if WIN32
    if(argc>1){
        // HMODULE test = LoadLibraryA("hook_dll.dll");
        // int ret = GetLastError();

        std::thread([&out_stream] {
            std::string line;
            while (std::getline(out_stream, line))
                std::cout << line << std::endl;
        }).detach();

        boost::filesystem::path fpath(argv[1]);
        child = boost::process::child(fpath,boost::process::std_out>out_stream,boost::process::start_dir(fpath.parent_path()));

        boost::filesystem::path dllpath(HOOK_DLL);
        inject(boost::filesystem::system_complete(dllpath).string(), child);
        signal(SIGABRT,[](int){child.terminate();});

        callfunc(boost::filesystem::system_complete(dllpath).string(),child, "Message","Hello");

        child.wait();
        out_stream.pipe().close();
    }
#endif
}