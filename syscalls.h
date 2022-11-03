#pragma once
#include <Windows.h>

typedef VOID(WINAPI* RtlGetNtVersionNumbers_t)(LPDWORD pMajor, LPDWORD pMinor, LPDWORD pBuild);
typedef NTSTATUS(WINAPI* NtQuerySystemInformation_t)(ULONG sysInfoClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
typedef NTSTATUS(WINAPI* NtQueryObject_t)(HANDLE ObjectHandle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG Length, PULONG ResultLength);