#pragma once
#include <Windows.h>

typedef VOID(WINAPI* RtlGetNtVersionNumbers_t)(LPDWORD pMajor, LPDWORD pMinor, LPDWORD pBuild);
typedef NTSTATUS(WINAPI* NtQuerySystemInformation_t)(ULONG sysInfoClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
typedef NTSTATUS(WINAPI* NtQueryObject_t)(HANDLE ObjectHandle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG Length, PULONG ResultLength);
typedef NTSTATUS(NTAPI* NtSetInformationProcess_t) (HANDLE processHandle, PROCESS_INFORMATION_CLASS infoClass, PVOID info, ULONG infoLength);

RtlGetNtVersionNumbers_t sRtlGetNtVersionNumbers;
NtQuerySystemInformation_t sNtQuerySystemInformation;
NtQueryObject_t sNtQueryObject;
NtSetInformationProcess_t sNtSetInformationProcess;

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

    sNtSetInformationProcess = (NtSetInformationProcess_t)GetProcAddress(hNtdll, "NtSetInformationProcess");
    if (!sNtSetInformationProcess)
    {
        printf("[!] Error resolving NtSetInformationProcess syscall");
        return FALSE;
    }

    return TRUE;
}