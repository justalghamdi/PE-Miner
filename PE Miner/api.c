#include "api.h"

BOOL IsAppAlreadyRun() {
	CreateMutex(0, FALSE, "Local\\devil_Inject");
	if (GetLastError() == ERROR_ALREADY_EXISTS) {
		return TRUE;
	}
	return FALSE;
}

BOOL EnableVirtualProcessing() {
	hOut = GetStdHandle(STD_OUTPUT_HANDLE);
	DWORD dwMode;
	GetConsoleMode(hOut, &dwMode);
	dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
	return SetConsoleMode(hOut, dwMode);
}
BOOL _CreateFile(char* path) {
    HANDLE hFile = CreateFileA(
        path,
        GENERIC_READ | GENERIC_WRITE,
        (int)NULL,
        NULL,
        CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (GetLastError() == ERROR_ALREADY_EXISTS || GetLastError() == ERROR_FILE_EXISTS) {
        CloseHandle(hFile);
        return FALSE;
    }
    CloseHandle(hFile);
    return TRUE;
}