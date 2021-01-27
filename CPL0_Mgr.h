class kCtx
{
private:
	PBYTE FindPattern_Wrapper(const char* Pattern, ULONG64 Module1)
	{
		//find pattern utils
		#define InRange(x, a, b) (x >= a && x <= b) 
		#define GetBits(x) (InRange(x, '0', '9') ? (x - '0') : ((x - 'A') + 0xA))
		#define GetByte(x) ((BYTE)(GetBits(x[0]) << 4 | GetBits(x[1])))

		//get module range
		PBYTE ModuleStart = (PBYTE)Module1; if (!ModuleStart) return nullptr;
		PIMAGE_NT_HEADERS NtHeader = ((PIMAGE_NT_HEADERS)(ModuleStart + ((PIMAGE_DOS_HEADER)ModuleStart)->e_lfanew));
		PBYTE ModuleEnd = (PBYTE)(ModuleStart + NtHeader->OptionalHeader.SizeOfImage - 0x1000); ModuleStart += 0x1000;

		//scan pattern main
		PBYTE FirstMatch = nullptr;
		const char* CurPatt = Pattern;
		for (; ModuleStart < ModuleEnd; ++ModuleStart)
		{
			bool SkipByte = (*CurPatt == '\?');
			if (SkipByte || *ModuleStart == GetByte(CurPatt)) {
				if (!FirstMatch) FirstMatch = ModuleStart;
				SkipByte ? CurPatt += 2 : CurPatt += 3;
				if (CurPatt[-1] == 0) return FirstMatch;
			}

			else if (FirstMatch) {
				ModuleStart = FirstMatch;
				FirstMatch = nullptr;
				CurPatt = Pattern;
			}
		}

		return nullptr;
	}

public:
	uint64_t GetDriverBase(const char* Name, char* FullPath = nullptr)
	{
		//get all system modules
		Loop: ULONG Size = 0;
		FC(ntdll, NtQuerySystemInformation, (SYSTEM_INFORMATION_CLASS)11, nullptr, Size, &Size);
		PRTL_PROCESS_MODULES ModInfo = (PRTL_PROCESS_MODULES)malloc1(Size);
		if (FC(ntdll, NtQuerySystemInformation, (SYSTEM_INFORMATION_CLASS)11, ModInfo, Size, &Size)) {
			free1(ModInfo); goto Loop;
		}

		//process list
		uint64_t Base = 0;
		for (ULONG i = 0; i < ModInfo->NumberOfModules; i++) {
			if (StrCmp(Name, (char*)ModInfo->Modules[i].FullPathName + ModInfo->Modules[i].OffsetToFileName, false))
			{
				//only windir drivers
				if (!StrCmp(E("\\SystemRoot\\"), (char*)ModInfo->Modules[i].FullPathName, false)) {
					break;
				}

				//build file name
				if (FullPath) {
					FC(kernel32, GetWindowsDirectoryA, FullPath, 64); StrCat(FullPath, "\\");
					StrCat(FullPath, (char*)&ModInfo->Modules[i].FullPathName[12]);
				}

				//set module base
				Base = (uint64_t)ModInfo->Modules[i].ImageBase;
				break;
			}
		}

		//cleanup & ret
		free1(ModInfo);
		return Base;
	}

	PVOID Resolve(const char* Name, const char* Module = nullptr)
	{
		char sysfilePath[64]; sysfilePath[0] = 0;
		auto ModName = Module ? Module : E("ntoskrnl.exe");
		uint64_t ModBase = GetDriverBase(ModName, sysfilePath), Func = 0;

		if (!ModBase)
			return nullptr;

		auto hMod = FC(kernel32, LoadLibraryExA, sysfilePath, nullptr, DONT_RESOLVE_DLL_REFERENCES);

		auto ptr = (uint64_t)GetProcAddress(hMod, Name);
		if (ptr) {
			Func = ModBase + (ptr - (uint64_t)hMod);
		}

		FC(kernel32, FreeLibrary, hMod);

		if (!Func) {
			auto ptr = (uint64_t)GetSymAddress(sysfilePath, Name);
			if (ptr) Func = ModBase + ptr;
		}

		return (PVOID)Func;
	}

	PBYTE FindPattern(const char* Pattern, const char* Module = nullptr)
	{
		char sysfilePath[64]; sysfilePath[0] = 0;
		auto ModName = Module ? Module : E("ntoskrnl.exe");
		uint64_t ModBase = GetDriverBase(ModName, sysfilePath), Func = 0;

		if (!ModBase)
			return nullptr;

		auto hMod = FC(kernel32, LoadLibraryExA, sysfilePath, nullptr, DONT_RESOLVE_DLL_REFERENCES);

		auto ptr = FindPattern_Wrapper(Pattern, (uint64_t)hMod);
		if (ptr) {
			Func = ModBase + ((uint64_t)ptr - (uint64_t)hMod);
		}

		FC(kernel32, FreeLibrary, hMod);

		return (PBYTE)Func;
	}

	PVOID RVA(ULONG64 Instr, int InstrSz, const char* Module = nullptr)
	{
		char sysfilePath[64]; sysfilePath[0] = 0;
		auto ModName = Module ? Module : E("ntoskrnl.exe");
		uint64_t ModBase = GetDriverBase(ModName, sysfilePath), Func = 0;

		if (!ModBase)
			return nullptr;

		auto hMod = FC(kernel32, LoadLibraryExA, sysfilePath, nullptr, DONT_RESOLVE_DLL_REFERENCES);

		auto ptr1 = (uint64_t)hMod + (Instr - ModBase);
		auto ptr2 = ((DWORD64)ptr1 + InstrSz + *(LONG*)((DWORD64)ptr1 + (InstrSz - sizeof(LONG))));
		Func = ModBase + (ptr2 - (uint64_t)hMod);

		FC(kernel32, FreeLibrary, hMod);

		return (PVOID)Func;
	}

	pte* GetPte(ULONG64 Addr) {
		static PVOID kgetpte = 0;
		if (!kgetpte) kgetpte = Resolve(E("MiGetPteAddress"));
		return CallInKernel<pte*>(kgetpte, Addr);
	}

	void MemCpy(PVOID Dst, PVOID Src, ULONG64 Size) {
		static PVOID kmemcpy = 0;
		if (!kmemcpy) kmemcpy = this->Resolve(E("memcpy"));
		CallInKernel(kmemcpy, Dst, Src, Size);
	}

	//kmemory mgr
	template<typename RetT = void, typename AddrT>
	RetT ReadVA_T(AddrT Ptr) {
		RetT Data{};
		this->MemCpy(&Data, (PVOID)Ptr, (ULONG64)sizeof(RetT));
		return Data;
	}

	template<typename DataT, typename AddrT>
	void WriteVA_T(AddrT Ptr, DataT Data) {
		this->MemCpy((PVOID)Ptr, &Data, (ULONG64)sizeof(DataT));
	}

	template<typename RetT = void, typename FnT, typename A1T = void*, typename A2T = void*, typename A3T = void*, typename A4T = void*, typename A5T = void*, typename A6T = void*, typename A7T = void*, typename A8T = void*>
	RetT CallInKernel(FnT FuncPtr, A1T Arg1 = A1T{}, A2T Arg2 = A2T{}, A3T Arg3 = A3T{}, A4T Arg4 = A4T{}, A5T Arg5 = A5T{}, A6T Arg6 = A6T{}, A7T Arg7 = A7T{}, A8T Arg8 = A8T{})
	{
		static uint64_t CallPtr = 0;
		if (!CallPtr) {
			CallPtr = (uint64_t)GetProcAddress(GetModuleHandleA("ntdll"), "NtQueryInformationPort");
		}
#pragma pack(push, 1)
		struct CallStuct { bool useless; ULONG64 HashRet; PVOID Func; A1T Arg1; A2T Arg2; A3T Arg3; A4T Arg4; A5T Arg5; A6T Arg6; A7T Arg7; A8T Arg8; };
#pragma pack(pop)
		typedef DWORD64(__fastcall* CallBDFn)(DWORD64, DWORD64, CallStuct*, int, DWORD64);
		CallStuct CallCtx{ 0, 0xFACEDEADFEEDC0DE, (PVOID)FuncPtr, Arg1, Arg2, Arg3, Arg4, Arg5, Arg6, Arg7, Arg8 };


		auto ret = ((CallBDFn)CallPtr)(0, 0, (CallStuct*)(((ULONG64)&CallCtx) + 1), 8, 0);

		printf("%p %p %p\n\n", &CallCtx.HashRet, CallCtx.HashRet, ret);

		return (RetT)CallCtx.HashRet;
	}
};

kCtx CPL0;