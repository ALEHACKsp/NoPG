#pragma comment(linker,"/MERGE:.rdata=.text")
#pragma comment(linker,"/MERGE:.pdata=.text")

#include <Windows.h>
#include <intrin.h>
#include <stdint.h>
#include <DbgHelp.h>

//internals
#define NtCurrentProcess() ((HANDLE)-1)
#define SymFolderCleanup() GetSymAddress(L"", "", true)
#define DWORD2BYTES(Val) (BYTE)(Val), (BYTE)(Val >> 8), (BYTE)(Val >> 16), (BYTE)(Val >> 24)
#define RtlImageNtHeader(Mod) ((PIMAGE_NT_HEADERS)((uint8_t*)Mod + ((PIMAGE_DOS_HEADER)Mod)->e_lfanew))
#define RVA(Buff, Instr, InstrSize) ((uint64_t)Instr + InstrSize + *(long*)(RVA_VA(Buff, (uint64_t)Instr + (InstrSize - 4))))

#include "MiniCRT.h"
#include "Utils.h"
#include "Bytes.h"