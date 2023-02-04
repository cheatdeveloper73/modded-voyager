#pragma once

#define START_BOOT_APPLICATION_SIG "\x48\x8B\xC4\x48\x89\x58\x20\x44\x89\x40\x18\x48\x89\x50\x10\x48\x89\x48\x08\x55\x56\x57\x41\x54"
#define START_BOOT_APPLICATION_MASK "xxxxxxxxxxxxxxxxxxxxxxxx"

#define WINDOWS_BOOTMGFW_PATH L"\\efi\\microsoft\\boot\\bootmgfw.efi"
#define WINDOWS_BOOTMGFW_BACKUP_PATH L"\\efi\\microsoft\\boot\\bootmgfw.efi.backup"

typedef EFI_STATUS(EFIAPI* IMG_ARCH_START_BOOT_APPLICATION)(VOID*, VOID*, UINT32, UINT8, VOID*);

EFI_STATUS EFIAPI RestoreBootMgfw(UINT32* Index);
EFI_STATUS EFIAPI SetBootCurrentToWindowsBootmgr();
EFI_STATUS EFIAPI GetBootMgfwPath(/*UINT32 Index,*/ EFI_DEVICE_PATH_PROTOCOL** BootMgfwDevicePath);
EFI_STATUS EFIAPI InstallBootMgfwHooks(EFI_HANDLE ImageHandle);
