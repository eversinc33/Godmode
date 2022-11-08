#include <Windows.h>

int main() 
{
    const char * pipeName = "\\\\.\\pipe\\TestPipe";
    const char * buffWrite = "SOME TEXT";
    unsigned buffLength = strlen(buffWrite);
    char buffRead[1024];
    DWORD nWritten, nRead;

    HANDLE hFile = CreateFile(pipeName, GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
    WriteFile(hFile, buffWrite, buffLength, &nWritten, 0);
    CloseHandle(hFile);

    return 0;
}