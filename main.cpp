#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <Windows.h>
#include <TlHelp32.h>

struct MappingData {
    BYTE* pBase;
    PIMAGE_NT_HEADERS pNtHeaders;
    decltype(GetProcAddress)* pGetProcAddress;
    decltype(LoadLibraryA)* pLoadLibraryA;
};

#pragma runtime_checks("", off)
static DWORD __stdcall Shellcode(MappingData* pData) {
    if (!pData) return 0;

    BYTE* pBase = pData->pBase;
    auto* pNtHeaders = pData->pNtHeaders;
    auto* pOptHeader = &pNtHeaders->OptionalHeader;

    auto fLoadLibraryA = pData->pLoadLibraryA;
    auto fGetProcAddress = pData->pGetProcAddress;

    auto* pRelocDir = &pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (pRelocDir->Size) {
        auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pRelocDir->VirtualAddress);
        DWORD_PTR delta = reinterpret_cast<DWORD_PTR>(pBase) - pOptHeader->ImageBase;

        while (pRelocData->VirtualAddress) {
            DWORD amountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);

            for (DWORD i = 0; i < amountOfEntries; ++i) {
                if ((pRelativeInfo[i] >> 12) == IMAGE_REL_BASED_DIR64 || (pRelativeInfo[i] >> 12) == IMAGE_REL_BASED_HIGHLOW) {
                    DWORD_PTR* pPatch = reinterpret_cast<DWORD_PTR*>(pBase + pRelocData->VirtualAddress + (pRelativeInfo[i] & 0xFFF));
                    *pPatch += delta;
                }
            }
            pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
        }
    }

    auto* pImportDir = &pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (pImportDir->Size) {
        auto* pImportDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pImportDir->VirtualAddress);
        while (pImportDesc->Name) {
            char* szMod = reinterpret_cast<char*>(pBase + pImportDesc->Name);
            HINSTANCE hMod = fLoadLibraryA(szMod);

            auto* pThunkRef = reinterpret_cast<IMAGE_THUNK_DATA*>(pBase + pImportDesc->OriginalFirstThunk);
            auto* pFuncRef = reinterpret_cast<IMAGE_THUNK_DATA*>(pBase + pImportDesc->FirstThunk);

            if (!pThunkRef) pThunkRef = pFuncRef;

            while (pThunkRef->u1.AddressOfData) {
                if (IMAGE_SNAP_BY_ORDINAL(pThunkRef->u1.Ordinal)) {
                    pFuncRef->u1.Function = reinterpret_cast<DWORD_PTR>(fGetProcAddress(hMod, reinterpret_cast<char*>(pThunkRef->u1.Ordinal & 0xFFFF)));
                }
                else {
                    auto* pImportByName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + pThunkRef->u1.AddressOfData);
                    pFuncRef->u1.Function = reinterpret_cast<DWORD_PTR>(fGetProcAddress(hMod, pImportByName->Name));
                }
                pThunkRef++;
                pFuncRef++;
            }
            pImportDesc++;
        }
    }

    auto* pTLSDir = &pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (pTLSDir->Size) {
        auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pTLSDir->VirtualAddress);
        auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
        while (pCallback && *pCallback) {
            (*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
            pCallback++;
        }
    }

    if (pOptHeader->AddressOfEntryPoint) {
        using DllMainFn = BOOL(__stdcall*)(HINSTANCE, DWORD, LPVOID);
        auto fDllMain = reinterpret_cast<DllMainFn>(pBase + pOptHeader->AddressOfEntryPoint);
        return fDllMain(reinterpret_cast<HINSTANCE>(pBase), DLL_PROCESS_ATTACH, nullptr);
    }

    return 1;
}
static void __stdcall ShellcodeEnd() {}
#pragma runtime_checks("", on)

DWORD GetProcessIdByName(const std::wstring& procName) {
    DWORD procId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnap, &pe)) {
            do {
                if (procName == pe.szExeFile) {
                    procId = pe.th32ProcessID;
                    break;
                }
            } while (Process32NextW(hSnap, &pe));
        }
    }
    CloseHandle(hSnap);
    return procId;
}

bool ManualMap(HANDLE hProc, const char* dllPath) {
    std::ifstream file(dllPath, std::ios::binary | std::ios::ate);
    if (file.fail()) {
        std::cout << " [-] Failed to open DLL file.\n";
        return false;
    }

    size_t fileSize = file.tellg();
    std::vector<BYTE> fileBuffer(fileSize);
    file.seekg(0, std::ios::beg);
    file.read(reinterpret_cast<char*>(fileBuffer.data()), fileSize);
    file.close();

    auto* pDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(fileBuffer.data());
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        std::cout << " [-] Invalid DOS signature.\n";
        return false;
    }

    auto* pNtHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(fileBuffer.data() + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        std::cout << " [-] Invalid NT signature.\n";
        return false;
    }

    BYTE* pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, pNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!pTargetBase) {
        std::cout << " [-] Failed to allocate memory in target process.\n";
        return false;
    }

    WriteProcessMemory(hProc, pTargetBase, fileBuffer.data(), pNtHeaders->OptionalHeader.SizeOfHeaders, nullptr);

    auto* pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    for (UINT i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i) {
        if (pSectionHeader[i].SizeOfRawData) {
            WriteProcessMemory(hProc, pTargetBase + pSectionHeader[i].VirtualAddress, fileBuffer.data() + pSectionHeader[i].PointerToRawData, pSectionHeader[i].SizeOfRawData, nullptr);
        }
    }

    MappingData data;
    data.pBase = pTargetBase;
    data.pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(pTargetBase + pDosHeader->e_lfanew);
    data.pLoadLibraryA = LoadLibraryA;
    data.pGetProcAddress = GetProcAddress;

    BYTE* pMappingDataTarget = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, sizeof(MappingData), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    WriteProcessMemory(hProc, pMappingDataTarget, &data, sizeof(MappingData), nullptr);

    size_t shellcodeSize = reinterpret_cast<DWORD_PTR>(ShellcodeEnd) - reinterpret_cast<DWORD_PTR>(Shellcode);
    BYTE* pShellcodeTarget = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    WriteProcessMemory(hProc, pShellcodeTarget, reinterpret_cast<void*>(Shellcode), shellcodeSize, nullptr);

    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcodeTarget), pMappingDataTarget, 0, nullptr);
    if (!hThread) {
        std::cout << " [-] Failed to create remote thread.\n";
        VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, pMappingDataTarget, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, pShellcodeTarget, 0, MEM_RELEASE);
        return false;
    }

    std::cout << " [*] Running shellcode...\n";
    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(hThread);
    VirtualFreeEx(hProc, pMappingDataTarget, 0, MEM_RELEASE);
    VirtualFreeEx(hProc, pShellcodeTarget, 0, MEM_RELEASE);
    return true;
}

std::string version_type;

void DrawUI() {

    std::cout << " +---------------------------------------+\n";
    std::cout << " |        MINI-INJECTOR.",version_type,"              |\n";
    std::cout << " +---------------------------------------+\n\n";
}

int main() {
#ifdef _WIN64
    version_type = " \033[32mx64 Version\033[0m\n";
#else
    version_type = " \033[32mx32 Version\033[0m\n";
#endif
    std::wstring processName;
    std::string dllPath;

    DrawUI();

    std::cout << " \033[36m[>]\033[0m Enter target process (e.g., target.exe): ";
    std::getline(std::wcin, processName);

    std::cout << " \033[36m[>]\033[0m Enter path to .dll file: ";
    std::getline(std::cin, dllPath);

    if (!dllPath.empty() && dllPath.front() == '"' && dllPath.back() == '"') {
        dllPath = dllPath.substr(1, dllPath.length() - 2);
    }

    std::cout << "\n +---------------- STATUS ----------------+\n";

    DWORD procId = GetProcessIdByName(processName);
    if (!procId) {
        std::cout << " \033[31m[-]\033[0m | Process not found.\n";
        std::cout << " +---------------------------------------+\n\n";
        system("pause");
        return 0;
    }

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procId);
    if (!hProc) {
        std::cout << " \033[31m[-]\033[0m | OpenProcess failed (Run as Admin).\n";
        std::cout << " +---------------------------------------+\n\n";
        system("pause");
        return 0;
    }

    if (ManualMap(hProc, dllPath.c_str())) {
        std::cout << " \033[32m[+]\033[0m | Injection successful!\n";
    }
    else {
        std::cout << " \033[31m[-]\033[0m | Injection failed.\n";
    }

    std::cout << " +---------------------------------------+\n\n";

    CloseHandle(hProc);
    system("pause");
    return 0;
}
