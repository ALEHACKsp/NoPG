#pragma comment(linker,"/MERGE:.rdata=.text")
#pragma comment(linker,"/MERGE:.pdata=.text")

#include <Windows.h>
#include <iostream>
//#include <shlwapi.h>
#include <intrin.h>
#include <winternl.h>
#include <stdint.h>
//#pragma comment(lib, "Shlwapi.lib")

//internals
#define NtCurrentProcess() ((HANDLE)-1)
#define NtTerminateProcess() SysCall(44, NtCurrentProcess(), 0ull)
#define DWORD2BYTES(Val) (BYTE)(Val), (BYTE)(Val >> 8), (BYTE)(Val >> 16), (BYTE)(Val >> 24)
#define RtlImageNtHeader(Mod) ((PIMAGE_NT_HEADERS)((uint8_t*)Mod + ((PIMAGE_DOS_HEADER)Mod)->e_lfanew))
#define RVA(Buff, Instr, InstrSize) ((uint64_t)Instr + InstrSize + *(long*)(RVA_VA(Buff, (uint64_t)Instr + (InstrSize - 4))))

#include "MiniCRT.h"

#include "Utils.h"
#include "Symbol.h"
#include "Bytes.h"