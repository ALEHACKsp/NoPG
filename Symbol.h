//#include <aclapi.h>
#include <DbgHelp.h>
//#include <sddl.h>

//#pragma comment(lib, "Imagehlp.lib")
#pragma comment(lib, "Dbghelp.lib")

#define SymFolderCleanup() GetSymAddress((""), (""), true)

uint8_t* GetSymAddress(const wchar_t* FilePath, const char* SymName, bool Cleanup = false)
{
	//build pdb path
	char symPath[MAX_PATH]; *(uint32_t*)&symPath[0] = 0x2A565253;
	GetWindowsDirectoryA((char*)&symPath[4], 64);
	StrCat(symPath, Cleanup ? ("\\Temp\\symTmp") : ("\\Temp\\symTmp*http://msdl.microsoft.com/download/symbols"));

	//clean folder
	if (Cleanup) {
		symPath[StrLen(symPath) + 1] = 0; //double null meme

		SHFILEOPSTRUCTA shfo = {
		   NULL,
		   FO_DELETE,
		   &symPath[4],
		   NULL,
		   FOF_NO_UI,
		   FALSE,
		   NULL,
		   NULL
		};

		//SHFileOperationA(&shfo);
		return nullptr;
	}

	//init pdb engine
	SymInitialize(NtCurrentProcess(), symPath, false);

	//set output mode
	SymSetOptions(SYMOPT_IGNORE_NT_SYMPATH /*| SYMOPT_DEBUG*/ | SYMOPT_ALLOW_ABSOLUTE_SYMBOLS);

	//load pdb file
	auto ModBase = SymLoadModuleExW(NtCurrentProcess(), nullptr, FilePath, nullptr, 0, 0, nullptr, 0);
	if (!ModBase) {
		SymCleanup(NtCurrentProcess());
		return nullptr;
	}

	//get pdb path
	IMAGEHLP_MODULEW64 ModuleInfo;
	ModuleInfo.SizeOfStruct = sizeof(IMAGEHLP_MODULEW64);
	SymGetModuleInfoW64(NtCurrentProcess(), ModBase, &ModuleInfo);

	//build symbol name
	char SymNameFix[64];
	StrCpy(ModuleInfo.ModuleName, SymNameFix);
	StrCat(SymNameFix, ("!"));
	StrCat(SymNameFix, SymName);

	//get func
	PBYTE ResolvedFunc = nullptr;
	PSYMBOL_INFO_PACKAGE SIP = (PSYMBOL_INFO_PACKAGE)_alloca(sizeof(SYMBOL_INFO_PACKAGE));
	SIP->si.MaxNameLen = sizeof(SIP->name);
	SIP->si.SizeOfStruct = sizeof(SYMBOL_INFO);
	if (SymFromName(NtCurrentProcess(), SymNameFix, &SIP->si)) {
		ResolvedFunc = (PBYTE)SIP->si.Address - ModBase;
	}

	//cleanup
	SymUnloadModule64(NtCurrentProcess(), ModBase);
	SymCleanup(NtCurrentProcess());

	//ret func offset
	return ResolvedFunc;
}