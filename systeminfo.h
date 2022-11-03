#pragma once
#include <Windows.h>
#include "syscalls.h"

BOOL print_version(HMODULE hNtdll)
{
    RtlGetNtVersionNumbers_t RtlGetNtVersionNumbers = (RtlGetNtVersionNumbers_t)GetProcAddress(hNtdll, "RtlGetNtVersionNumbers");
    if (RtlGetNtVersionNumbers == 0)
    {
        printf("[!] Error getting syscall from ntdll...");
        return FALSE;
    }
    DWORD major_version;
    DWORD minor_version;
    DWORD build_number;
    RtlGetNtVersionNumbers(&major_version, &minor_version, &build_number);
    printf("[*] Running on: WIN %u.%u Build %u\n", major_version, minor_version, build_number);
    return TRUE;
}