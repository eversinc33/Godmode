#pragma once
#include <Windows.h>
#include "syscalls.h"

BOOL print_version()
{
    DWORD major_version;
    DWORD minor_version;
    DWORD build_number;
    sRtlGetNtVersionNumbers(&major_version, &minor_version, &build_number);
    printf("[*] Running on: WIN %u.%u Build %u\n", major_version, minor_version, build_number);
    return TRUE;
}