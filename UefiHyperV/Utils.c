#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <IndustryStandard/PeImage.h>
#include <Guid/GlobalVariable.h>
#include "PeStructs.h"
#include "Utils.h"

UINT16 BuildNumber = 0;

#define EFI_IMAGE_SUBSYSTEM_NATIVE						1
#define EFI_IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION	16

#define LDR_IS_DATAFILE(x)				(((UINTN)(x)) & (UINTN)1)
#define LDR_DATAFILE_TO_VIEW(x)			((VOID*)(((UINTN)(x)) & ~(UINTN)1))
#define IMAGE32(NtHeaders) ((NtHeaders)->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
#define IMAGE64(NtHeaders) ((NtHeaders)->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
#define HEADER_FIELD(NtHeaders, Field) (IMAGE64(NtHeaders) ? ((PIMAGE_NT_HEADERS64)(NtHeaders))->OptionalHeader.Field : ((PIMAGE_NT_HEADERS32)(NtHeaders))->OptionalHeader.Field)
#define FIELD_OFFSET(Type, Field)	((INT32)(INTN)&(((Type *)0)->Field))
#define IMAGE_FIRST_SECTION(NtHeaders) ((PIMAGE_SECTION_HEADER)((UINTN)(NtHeaders) + FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader) + ((NtHeaders))->FileHeader.SizeOfOptionalHeader))
#define MAKELANGID(Primary, Sub)	((((UINT16)(Sub)) << 10) | (UINT16)(Primary))
#define LANG_NEUTRAL				0x00
#define SUBLANG_NEUTRAL				0x00
#define RT_VERSION					16
#define VS_VERSION_INFO				1
#define VS_FF_DEBUG					(0x00000001L)
#define LOWORD(l)					((UINT16)(((UINTN)(l)) & 0xffff))
#define HIWORD(l)					((UINT16)((((UINTN)(l)) >> 16) & 0xffff))
#define LOBYTE(w)					((UINT8)(((UINTN)(w)) & 0xff))
#define HIBYTE(w)					((UINT8)((((UINTN)(w)) >> 8) & 0xff))

BOOLEAN CheckMask(CHAR8* base, CHAR8* pattern, CHAR8* mask)
{
	for (; *mask; ++base, ++pattern, ++mask)
		if (*mask == 'x' && *base != *pattern)
			return FALSE;

	return TRUE;
}

VOID* FindPattern(CHAR8* base, UINTN size, CHAR8* pattern, CHAR8* mask)
{
	size -= AsciiStrLen(mask);
	for (UINTN i = 0; i <= size; ++i)
	{
		VOID* addr = &base[i];
		if (CheckMask(addr, pattern, mask))
			return addr;
	}
	return NULL;
}

VOID* GetExport(UINT8* ModuleBase, CHAR8* export)
{
	EFI_IMAGE_DOS_HEADER* dosHeaders = (EFI_IMAGE_DOS_HEADER*)ModuleBase;
	if (dosHeaders->e_magic != EFI_IMAGE_DOS_SIGNATURE)
		return NULL;

	EFI_IMAGE_NT_HEADERS64* ntHeaders = (EFI_IMAGE_NT_HEADERS64*)(ModuleBase + dosHeaders->e_lfanew);
	UINT32 exportsRva = ntHeaders->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	EFI_IMAGE_EXPORT_DIRECTORY* exports = (EFI_IMAGE_EXPORT_DIRECTORY*)(ModuleBase + exportsRva);
	UINT32* nameRva = (UINT32*)(ModuleBase + exports->AddressOfNames);

	for (UINT32 i = 0; i < exports->NumberOfNames; ++i)
	{
		CHAR8* func = (CHAR8*)(ModuleBase + nameRva[i]);
		if (AsciiStrCmp(func, export) == 0)
		{
			UINT32* funcRva = (UINT32*)(ModuleBase + exports->AddressOfFunctions);
			UINT16* ordinalRva = (UINT16*)(ModuleBase + exports->AddressOfNameOrdinals);
			return (VOID*)(((UINT64)ModuleBase) + funcRva[ordinalRva[i]]);
		}
	}
	return NULL;
}

VOID MemCopy(VOID* dest, VOID* src, UINTN size) 
{
	for (UINT8* d = dest, *s = src; size--; *d++ = *s++);
}

VOID* MemSet(VOID* dest, int val, UINT32 len)
{
	unsigned char* ptr = (unsigned char*)(dest);
	while (len-- > 0)
		*ptr++ = val;

	return dest;
}

int MemCmp(const void* s1, const void* s2, UINT32 n)
{
	const unsigned char* p1 = s1;
	const unsigned char* end1 = p1 + n;
	const unsigned char* p2 = s2;
	int d = 0;
	for (;;) 
	{
		if (d || p1 >= end1) 
			break;

		d = (int)*p1++ - (int)*p2++;
		if (d || p1 >= end1) 
			break;

		d = (int)*p1++ - (int)*p2++;
		if (d || p1 >= end1)
			break;

		d = (int)*p1++ - (int)*p2++;
		if (d || p1 >= end1) 
			break;

		d = (int)*p1++ - (int)*p2++;
	}
	return d;
}

STATIC BOOLEAN EFIAPI RtlIsCanonicalAddress(UINTN Address)
{
	return (((Address & 0xFFFF800000000000) + 0x800000000000) & ~0x800000000000) == 0;
}

PIMAGE_NT_HEADERS EFIAPI RtlpImageNtHeaderEx(IN CONST VOID* Base, IN UINTN Size OPTIONAL)
{
	CONST BOOLEAN RangeCheck = Size > 0;
	if (RangeCheck && Size < sizeof(IMAGE_DOS_HEADER))
		return NULL;

	if (((PIMAGE_DOS_HEADER)Base)->e_magic != EFI_IMAGE_DOS_SIGNATURE)
		return NULL;

	CONST UINT32 e_lfanew = ((PIMAGE_DOS_HEADER)Base)->e_lfanew;
	if (RangeCheck && (e_lfanew >= Size || e_lfanew >= (MAX_UINT32 - sizeof(EFI_IMAGE_NT_SIGNATURE) - sizeof(EFI_IMAGE_FILE_HEADER)) || e_lfanew + sizeof(EFI_IMAGE_NT_SIGNATURE) + sizeof(EFI_IMAGE_FILE_HEADER) >= Size))
		return NULL;

	CONST PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)(((UINT8*)Base) + e_lfanew);
	if (!RtlIsCanonicalAddress((UINTN)NtHeaders))
		return NULL;

	if (NtHeaders->Signature != EFI_IMAGE_NT_SIGNATURE)
		return NULL;

	return NtHeaders;
}

UINT32 EFIAPI RvaToOffset(IN PIMAGE_NT_HEADERS NtHeaders, IN UINT32 Rva)
{
	PIMAGE_SECTION_HEADER SectionHeaders = IMAGE_FIRST_SECTION(NtHeaders);
	CONST UINT16 NumberOfSections = NtHeaders->FileHeader.NumberOfSections;
	UINT32 Result = 0;
	for (UINT16 i = 0; i < NumberOfSections; ++i)
	{
		if (SectionHeaders->VirtualAddress <= Rva && SectionHeaders->VirtualAddress + SectionHeaders->Misc.VirtualSize > Rva)
		{
			Result = Rva - SectionHeaders->VirtualAddress + SectionHeaders->PointerToRawData;
			break;
		}
		SectionHeaders++;
	}
	return Result;
}

VOID* EFIAPI RtlpImageDirectoryEntryToDataEx(IN CONST VOID* Base, IN BOOLEAN MappedAsImage, IN UINT16 DirectoryEntry, OUT UINT32* Size)
{
	if (LDR_IS_DATAFILE(Base))
	{
		Base = LDR_DATAFILE_TO_VIEW(Base);
		MappedAsImage = FALSE;
	}

	CONST PIMAGE_NT_HEADERS NtHeaders = RtlpImageNtHeaderEx(Base, 0);
	if (NtHeaders == NULL)
		return NULL;

	if (DirectoryEntry >= HEADER_FIELD(NtHeaders, NumberOfRvaAndSizes))
		return NULL;

	CONST PIMAGE_DATA_DIRECTORY Directories = HEADER_FIELD(NtHeaders, DataDirectory);
	CONST UINT32 Rva = Directories[DirectoryEntry].VirtualAddress;
	if (Rva == 0)
		return NULL;

	*Size = Directories[DirectoryEntry].Size;
	if (MappedAsImage || Rva < HEADER_FIELD(NtHeaders, SizeOfHeaders))
		return (UINT8*)(Base)+Rva;

	return (UINT8*)(Base)+RvaToOffset(NtHeaders, Rva);
}

EFI_STATUS EFIAPI FindResourceDataById(IN CONST VOID* ImageBase, IN UINT16 TypeId, IN UINT16 NameId, IN UINT16 LanguageId OPTIONAL, OUT VOID** ResourceData OPTIONAL, OUT UINT32* ResourceSize)
{
	if (ResourceData != NULL)
		*ResourceData = NULL;

	*ResourceSize = 0;
	//ASSERT((!LDR_IS_DATAFILE(ImageBase)));

	UINT32 Size = 0;
	EFI_IMAGE_RESOURCE_DIRECTORY* ResourceDirTable = (EFI_IMAGE_RESOURCE_DIRECTORY*)RtlpImageDirectoryEntryToDataEx(ImageBase, TRUE, EFI_IMAGE_DIRECTORY_ENTRY_RESOURCE, &Size);
	if (ResourceDirTable == NULL || Size == 0)
		return EFI_NOT_FOUND;

	CONST UINT8* ResourceDirVa = (UINT8*)ResourceDirTable;
	EFI_IMAGE_RESOURCE_DIRECTORY_ENTRY* DirEntry = NULL;
	for (UINT16 i = ResourceDirTable->NumberOfNamedEntries; i < ResourceDirTable->NumberOfNamedEntries + ResourceDirTable->NumberOfIdEntries; ++i)
	{
		DirEntry = (EFI_IMAGE_RESOURCE_DIRECTORY_ENTRY*)((UINT8*)ResourceDirTable + sizeof(EFI_IMAGE_RESOURCE_DIRECTORY) + (i * sizeof(EFI_IMAGE_RESOURCE_DIRECTORY_ENTRY)));
		if ((BOOLEAN)DirEntry->u1.s.NameIsString)
			continue;
		if (DirEntry->u1.Id == TypeId && DirEntry->u2.s.DataIsDirectory)
			break;
	}
	if (DirEntry == NULL || DirEntry->u1.Id != TypeId)
		return EFI_NOT_FOUND;

	ResourceDirTable = (EFI_IMAGE_RESOURCE_DIRECTORY*)(ResourceDirVa + DirEntry->u2.s.OffsetToDirectory);
	DirEntry = NULL;
	for (UINT16 i = ResourceDirTable->NumberOfNamedEntries; i < ResourceDirTable->NumberOfNamedEntries + ResourceDirTable->NumberOfIdEntries; ++i)
	{
		DirEntry = (EFI_IMAGE_RESOURCE_DIRECTORY_ENTRY*)((UINT8*)ResourceDirTable + sizeof(EFI_IMAGE_RESOURCE_DIRECTORY) + (i * sizeof(EFI_IMAGE_RESOURCE_DIRECTORY_ENTRY)));
		if ((BOOLEAN)DirEntry->u1.s.NameIsString)
			continue;
		if (DirEntry->u1.Id == NameId && DirEntry->u2.s.DataIsDirectory)
			break;
	}
	if (DirEntry == NULL || DirEntry->u1.Id != NameId)
		return EFI_NOT_FOUND;

	ResourceDirTable = (EFI_IMAGE_RESOURCE_DIRECTORY*)(ResourceDirVa + DirEntry->u2.s.OffsetToDirectory);
	DirEntry = NULL;
	for (UINT16 i = ResourceDirTable->NumberOfNamedEntries; i < ResourceDirTable->NumberOfNamedEntries + ResourceDirTable->NumberOfIdEntries; ++i)
	{
		DirEntry = (EFI_IMAGE_RESOURCE_DIRECTORY_ENTRY*)((UINT8*)ResourceDirTable + sizeof(EFI_IMAGE_RESOURCE_DIRECTORY) + (i * sizeof(EFI_IMAGE_RESOURCE_DIRECTORY_ENTRY)));
		if ((BOOLEAN)DirEntry->u1.s.NameIsString)
			continue;
		if ((LanguageId == 0 || DirEntry->u1.Id == LanguageId) && !DirEntry->u2.s.DataIsDirectory)
			break;
	}
	if (DirEntry == NULL || (LanguageId != 0 && DirEntry->u1.Id != LanguageId))
		return EFI_INVALID_LANGUAGE;

	EFI_IMAGE_RESOURCE_DATA_ENTRY* DataEntry = (EFI_IMAGE_RESOURCE_DATA_ENTRY*)(ResourceDirVa + DirEntry->u2.OffsetToData);
	if (ResourceData != NULL)
		*ResourceData = (VOID*)((UINT8*)ImageBase + DataEntry->OffsetToData);

	*ResourceSize = DataEntry->Size;
	return EFI_SUCCESS;
}

typedef struct _VS_FIXEDFILEINFO
{
	UINT32 dwSignature; // 0xFEEF04BD
	UINT32 dwStrucVersion;
	UINT32 dwFileVersionMS;
	UINT32 dwFileVersionLS;
	UINT32 dwProductVersionMS;
	UINT32 dwProductVersionLS;
	UINT32 dwFileFlagsMask;
	UINT32 dwFileFlags;
	UINT32 dwFileOS;
	UINT32 dwFileType;
	UINT32 dwFileSubtype;
	UINT32 dwFileDateMS;
	UINT32 dwFileDateLS;
} VS_FIXEDFILEINFO;

typedef struct _VS_VERSIONINFO
{
	UINT16 TotalSize;
	UINT16 DataSize;
	UINT16 Type;
	CHAR16 Name[sizeof(L"VS_VERSION_INFO") / sizeof(CHAR16)];
	VS_FIXEDFILEINFO FixedFileInfo;
} VS_VERSIONINFO, * PVS_VERSIONINFO;

EFI_STATUS EFIAPI GetPeFileVersionInfo(IN CONST VOID* ImageBase, OUT UINT16* BuildNumber OPTIONAL, OUT UINT16* Revision OPTIONAL)
{
	VS_VERSIONINFO* VersionResource;
	UINT32 VersionResourceSize;
	CONST EFI_STATUS Status = FindResourceDataById(ImageBase, RT_VERSION, VS_VERSION_INFO, MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), (VOID**)&VersionResource, &VersionResourceSize);
	if (EFI_ERROR(Status))
		return Status;

	if (VersionResourceSize < sizeof(VS_VERSIONINFO) || StrnCmp(VersionResource->Name, L"VS_VERSION_INFO", (sizeof(L"VS_VERSION_INFO") / sizeof(CHAR16)) - 1) != 0 || VersionResource->FixedFileInfo.dwSignature != 0xFEEF04BD)
		return EFI_NOT_FOUND;

	if (BuildNumber != NULL)
		*BuildNumber = HIWORD(VersionResource->FixedFileInfo.dwFileVersionLS);
	if (Revision != NULL)
		*Revision = LOWORD(VersionResource->FixedFileInfo.dwFileVersionLS);

	return EFI_SUCCESS;
}

INPUT_FILETYPE EFIAPI GetInputFileType(IN CONST UINT8* ImageBase, IN UINTN ImageSize)
{
	if (*(UINT16*)ImageBase == 0xD5E9)
		return Bootmgr;

	CONST PIMAGE_NT_HEADERS NtHeaders = RtlpImageNtHeaderEx(ImageBase, ImageSize);
	if (NtHeaders == NULL)
		return Unknown;

	CONST UINT16 Subsystem = HEADER_FIELD(NtHeaders, Subsystem);
	if (Subsystem == EFI_IMAGE_SUBSYSTEM_NATIVE)
		return Ntoskrnl;

	if (Subsystem == EFI_IMAGE_SUBSYSTEM_EFI_APPLICATION)
	{
		CONST EFI_GUID BcdWindowsBootmgrGuid = { 0x9dea862c, 0x5cdd, 0x4e70, { 0xac, 0xc1, 0xf3, 0x2b, 0x34, 0x4d, 0x47, 0x95 } };
		for (UINT8* Address = (UINT8*)ImageBase; Address < ImageBase + ImageSize - sizeof(BcdWindowsBootmgrGuid); Address += sizeof(VOID*))
		{
			if (CompareGuid((CONST GUID*)Address, &BcdWindowsBootmgrGuid))
				return BootmgfwEfi;
		}
		return Unknown;
	}

	if (Subsystem != EFI_IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION)
		return Unknown;

	UINT32 Size = 0;
	EFI_IMAGE_RESOURCE_DIRECTORY* ResourceDirTable = RtlpImageDirectoryEntryToDataEx(ImageBase, TRUE, EFI_IMAGE_DIRECTORY_ENTRY_RESOURCE, &Size);
	if (ResourceDirTable == NULL || Size == 0)
		return Unknown;

	for (UINT8* Address = (UINT8*)ResourceDirTable; Address < ImageBase + ImageSize - sizeof(L"OSLOADER.XSL"); Address += sizeof(CHAR16))
	{
		if (CompareMem(Address, L"BOOTMGR.XSL", sizeof(L"BOOTMGR.XSL") - sizeof(CHAR16)) == 0)
		{
			return BootmgrEfi;
		}
		if (CompareMem(Address, L"OSLOADER.XSL", sizeof(L"OSLOADER.XSL") - sizeof(CHAR16)) == 0)
		{
			return WinloadEfi;
		}
	}
	return Unknown;
}
