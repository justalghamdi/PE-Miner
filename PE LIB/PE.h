#pragma once
#include <Windows.h>
#include <stdlib.h>
#include <string.h>
DWORD exeSize;
typedef struct pe {
	CHAR* PATH;
	BYTE* RawBinaryFile;
	DWORD PEsize;
	BOOL x64;
	PIMAGE_FILE_HEADER FILE_HEADER;
	PIMAGE_DOS_HEADER DOS_HEADER;
	PIMAGE_OPTIONAL_HEADER OPTIONAL_HEADER;
	PIMAGE_SECTION_HEADER SECTION_HEADER;
	PIMAGE_NT_HEADERS NT_HEADERS;
}PE;

typedef struct cave{
	DWORD Postion;
	DWORD VirtualAddress;
	DWORD PointerToRawData;
	DWORD ImageBase;
	size_t Size;
	DWORD Characteristics;
	int MinSize;
	char* CaveSectionName;

} CAVE;


PE ExeHeaders(char*);
BOOL IsASLR(PE* );
BOOL EnableASLR(PE*, BOOL);
CAVE FindCave(PE*,int);
void WriteToSection( PE*, DWORD, BYTE*,int);
BOOL ChangeSectionCharacteristics(char*, DWORD,PE*);
BOOL WriteExe(PE*);
