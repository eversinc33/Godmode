#pragma once
#include <Windows.h>

BOOL set_privilege(HANDLE token_handle, LPCTSTR privilege_name, BOOL should_enable)
{
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(NULL, privilege_name, &luid))
    {
        printf("[!] ERROR: LookupPrivilegeValue: %u\n", GetLastError());
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;

    if (should_enable)
    {
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    }
    else
    {
        tp.Privileges[0].Attributes = 0;
    }

    if (!AdjustTokenPrivileges(token_handle, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
    {
        printf("[!] ERROR: AdjustTokenPrivileges error: %u\n", GetLastError());
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
    {
        printf("[!] ERROR: The token does not have the specified privilege. \n");
        return FALSE;
    }

    return TRUE;
}

BOOL enable_privilege(BOOL is_impersonating, LPCTSTR privilege_name)
{
    HANDLE token;

    if (is_impersonating)
    {
        OpenThreadToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, TRUE, &token);
    }
    else
    {
        OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token);
    }

    printf("[*] Enabling %ws...\n", privilege_name);
    if (set_privilege(token, privilege_name, TRUE))
    {
        printf("[*] SUCCESS\n", privilege_name);
        return TRUE;
    }
    return FALSE;
}