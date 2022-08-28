#pragma once
#include "shared.h"

#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Shlwapi.lib")

#define BLK "\x1b[0;30m"
#define RED "\x1b[0;31m"
#define GRN "\x1b[0;32m"
#define YEL "\x1b[0;33m"
#define BLU "\x1b[0;34m"
#define MAG "\x1b[0;35m"
#define CYN "\x1b[0;36m"
#define WHT "\x1b[0;37m"
#define COLOR_RESET "\x1b[0m"

#define set_color(color) fputs(color, stdout)
#define reset_color()  fputs(COLOR_RESET,stdout)
#define ENABLE_UTF_16() _setmode(_fileno(stdout), 0x20000)
#define ENABLE_TEXT()   _setmode(_fileno(stdout), 0x4000) 
#define clear() system("cls")
#define pause() printf("\r\nPress Any Key To Exit...");system("pause > nul")
int Title(char* title);