#pragma once
#include "shared.h"

HANDLE hOut;
BOOL IsAppAlreadyRun();
BOOL EnableVirtualProcessing();
BOOL _CreateFile(char*);