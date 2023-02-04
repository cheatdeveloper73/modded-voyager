#pragma once

// 2004-1511 winload.BlImgAllocateImageBuffer E8 ?? ?? ?? ?? 8B D8 85 C0 78 ?? 21 7C 24 ?? 45 33 C0
#define ALLOCATE_IMAGE_BUFFER_SIG "\xE8\x00\x00\x00\x00\x8B\xD8\x85\xC0\x78\x00\x21\x7C\x24\x00\x45\x33\xC0"
#define ALLOCATE_IMAGE_BUFFER_MASK "x????xxxxx?xxx?xxx"

extern INLINE_HOOK WinLoadImageShitHook;
extern INLINE_HOOK WinLoadAllocateImageHook;
extern EFI_EXIT_BOOT_SERVICES ExitBootServicesOriginal;

typedef EFI_STATUS(EFIAPI* LDR_LOAD_IMAGE)(VOID* a1, VOID* a2, CHAR16* ImagePath, UINT64* ImageBasePtr, UINT32* ImageSize, VOID* a6, VOID* a7, VOID* a8, VOID* a9, VOID* a10, VOID* a11, VOID* a12, VOID* a13, VOID* a14, VOID* Arg15, VOID* Arg16);
typedef EFI_STATUS(EFIAPI* ALLOCATE_IMAGE_BUFFER)(VOID** imageBuffer, UINTN imageSize, UINT32 memoryType, UINT32 attributes, VOID* unused, UINT32 Value);

EFI_STATUS EFIAPI ExitBootServicesHook(EFI_HANDLE imageHandle, UINTN mapKey);
EFI_STATUS EFIAPI BlLdrLoadImage(VOID* Arg1, CHAR16* ModulePath, CHAR16* ModuleName, VOID* Arg4, VOID* Arg5, VOID* Arg6, VOID* Arg7, PPLDR_DATA_TABLE_ENTRY lplpTableEntry, VOID* Arg9, VOID* Arg10, VOID* Arg11, VOID* Arg12, VOID* Arg13, VOID* Arg14, VOID* Arg15, VOID* Arg16);
UINT64 EFIAPI BlImgAllocateImageBuffer(VOID** imageBuffer, UINTN imageSize, UINT32 memoryType, UINT32 attributes, VOID* unused, UINT32 Value);