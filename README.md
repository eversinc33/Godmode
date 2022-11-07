# godmode

WIP tool for playing with windows token manipulation.

```bash
priv module:
        priv.debug - enable debug priv
        priv.assign - enable assignprimarytoken priv

token module:
        token.current - show current security tokens
        token.revert - revert to self
        token.list - list available tokens for all system processes
        token.cmd - run cmd.exe with a token from token.list
        token.run - run any process with a token from token.list
        token.impersonate - impersonate a token from token.list
        token.pipe - create a named pipe and run cmd.exe, impersonating the first client that connects to it
        token.logon - logon a user with a password

        exit
```