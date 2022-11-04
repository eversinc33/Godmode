#pragma once
#include <Windows.h>

typedef VOID(WINAPI* RtlGetNtVersionNumbers_t)(LPDWORD pMajor, LPDWORD pMinor, LPDWORD pBuild);
typedef NTSTATUS(WINAPI* NtQuerySystemInformation_t)(ULONG sysInfoClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
typedef NTSTATUS(WINAPI* NtQueryObject_t)(HANDLE ObjectHandle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG Length, PULONG ResultLength);

RtlGetNtVersionNumbers_t sRtlGetNtVersionNumbers;
NtQuerySystemInformation_t sNtQuerySystemInformation;
NtQueryObject_t sNtQueryObject;

BOOL get_syscalls(HMODULE hNtdll)
{
	sRtlGetNtVersionNumbers = (RtlGetNtVersionNumbers_t)GetProcAddress(hNtdll, "RtlGetNtVersionNumbers");
    if (!sRtlGetNtVersionNumbers)
    {
        printf("[!] Error resolving RtlGetNtVersionNumbers syscall");
        return FALSE;
    }

    sNtQuerySystemInformation = (NtQuerySystemInformation_t)GetProcAddress(hNtdll, "NtQuerySystemInformation");
    if (!sNtQuerySystemInformation)
    {
        printf("[!] Error resolving NtQuerySystemInformation syscall");
        return FALSE;
    }

    sNtQueryObject = (NtQueryObject_t)GetProcAddress(hNtdll, "NtQueryObject");
    if (!sNtQueryObject)
    {
        printf("[!] Error resolving NtQueryObject syscall");
        return FALSE;
    }

    return TRUE;
}