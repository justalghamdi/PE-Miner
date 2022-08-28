#include "PE.h"


static BYTE* ReadExe(char* path) {
    HANDLE hExe = CreateFile(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hExe == INVALID_HANDLE_VALUE)
        return NULL;
    exeSize = GetFileSize(hExe, NULL);

    BYTE* pBin = calloc(exeSize, sizeof(BYTE));
    DWORD dw;

    ReadFile(hExe, pBin, exeSize, &dw, NULL);
    CloseHandle(hExe);
    return pBin;
}

PE ExeHeaders(char* path) {
    PE pe = {0};
    pe.PATH = path;
    pe.RawBinaryFile = ReadExe(path);
    pe.PEsize = exeSize;
    if (pe.RawBinaryFile == NULL) {
        return (PE) { NULL };
    }
    pe.DOS_HEADER = (PIMAGE_DOS_HEADER)pe.RawBinaryFile;
    if (pe.DOS_HEADER->e_magic != IMAGE_DOS_SIGNATURE)
        return (PE) { NULL }; //not PE
   
    pe.FILE_HEADER = (PIMAGE_FILE_HEADER)(pe.RawBinaryFile + pe.DOS_HEADER->e_lfanew + sizeof(DWORD));

    pe.x64 = pe.FILE_HEADER->Machine != IMAGE_FILE_MACHINE_I386;
    
    if (!pe.x64) {
        pe.NT_HEADERS = (PIMAGE_NT_HEADERS)((DWORD)pe.DOS_HEADER + pe.DOS_HEADER->e_lfanew);
        if (pe.NT_HEADERS->Signature != IMAGE_NT_SIGNATURE) {
            return (PE) { NULL };// NOT VAILD PE
        }
        pe.OPTIONAL_HEADER = (PIMAGE_OPTIONAL_HEADER)(pe.RawBinaryFile + pe.DOS_HEADER->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
        pe.SECTION_HEADER = (PIMAGE_SECTION_HEADER)(pe.RawBinaryFile + pe.DOS_HEADER->e_lfanew + sizeof(pe.NT_HEADERS));
       
    }
    else {
        pe.NT_HEADERS = (PIMAGE_NT_HEADERS64)((INT64)pe.DOS_HEADER + pe.DOS_HEADER->e_lfanew);
        if (pe.NT_HEADERS->Signature != IMAGE_NT_SIGNATURE) {
            return (PE) { NULL };// NOT VAILD PE
        }
        pe.OPTIONAL_HEADER = (PIMAGE_OPTIONAL_HEADER)(pe.RawBinaryFile + pe.DOS_HEADER->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
        pe.SECTION_HEADER = (PIMAGE_SECTION_HEADER)(pe.RawBinaryFile + pe.DOS_HEADER->e_lfanew + sizeof(pe.NT_HEADERS));
        
    }


    return pe;
}


BOOL IsASLR(PE* pe) {
    return pe->OPTIONAL_HEADER->DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
}
BOOL EnableASLR(PE* pe, BOOL enable) {
    if (!enable) {
        pe->OPTIONAL_HEADER->DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
        return IsASLR(pe) ? FALSE : TRUE;
    }
    pe->OPTIONAL_HEADER->DllCharacteristics |= IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
    return IsASLR(pe);
}

CAVE FindCave(PE* pe, int MinSize) {
    CAVE cave = { 0 };
    cave.MinSize = MinSize;
    WORD NumberOfSections = pe->FILE_HEADER->NumberOfSections;
    DWORD  PointerToRawData = -1, SizeofRawData = -1;
    PIMAGE_SECTION_HEADER Section;
    BYTE byte;
    int  i = 0,postion = 0, size = 0;
    for (Section = IMAGE_FIRST_SECTION(pe->NT_HEADERS), i = 0; i < pe->NT_HEADERS->FileHeader.NumberOfSections; ++i, Section++) {
        
        postion = 0;
        size = 0;
        PointerToRawData = Section->PointerToRawData;
        SizeofRawData = Section->SizeOfRawData;
        if (!SizeofRawData) {
            continue;
        }
        BYTE* p = pe->RawBinaryFile + Section->PointerToRawData;
        const BYTE* pEnd = p + Section->SizeOfRawData;
        while (p < pEnd)
        {
            byte = *p++;
            postion++;
            if (byte != 0x00) {
                if (size < cave.MinSize) {
                    size = 0;
                    continue;
                }
                cave.CaveSectionName = Section->Name;
                cave.Size = size;
                cave.ImageBase = pe->OPTIONAL_HEADER->ImageBase;
                cave.VirtualAddress = Section->VirtualAddress ;
                cave.Postion = postion;
                cave.PointerToRawData = Section->PointerToRawData ;
                cave.Characteristics = Section->Characteristics;
                return cave;
            }
            size++;
        }
    }
    return (CAVE){ NULL };
}



void WriteToSection(PE* pe, DWORD offest, BYTE* shell, int len) {
    BYTE* p = pe->RawBinaryFile + offest;
    for (int i = 0; i < len; i++) {
        p[i] = shell[i];
    }
}

BOOL ChangeSectionCharacteristics(char* SectionName, DWORD NewCharacteristics, PE*pe) {
    PIMAGE_SECTION_HEADER Section;
    int  i = 0;
    for (Section = IMAGE_FIRST_SECTION(pe->NT_HEADERS), i = 0; i < pe->NT_HEADERS->FileHeader.NumberOfSections; i++, Section++) {
        if (!strcmp(Section->Name, SectionName)) {
            Section->Characteristics = NewCharacteristics;
            return TRUE;
        }
    }
    return FALSE;
}

DWORD WriteExe(PE* pe) {
    HANDLE hExeFile = CreateFile(pe->PATH, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD byteswritten;
    WriteFile(hExeFile, pe->RawBinaryFile, pe->PEsize, &byteswritten, NULL);
    CloseHandle(hExeFile);
    return byteswritten;
}