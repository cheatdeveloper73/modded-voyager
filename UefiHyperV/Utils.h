#pragma once

#define SEC_TO_MS(seconds) seconds * 1000000

extern UINT16 BuildNumber;


#define SETION_NAME "zYaE"
#define BL_MEMORY_ATTRIBUTE_RWX 0x424000
#define SECTION_RWX (EFI_IMAGE_SCN_MEM_READ | EFI_IMAGE_SCN_MEM_WRITE | EFI_IMAGE_SCN_MEM_EXECUTE)
#define RESOLVE_RVA(SIG_RESULT, RIP_OFFSET, RVA_OFFSET) \
	(*(INT32*)(((UINT64)SIG_RESULT) + RVA_OFFSET)) + ((UINT64)SIG_RESULT) + RIP_OFFSET

typedef enum _INPUT_FILETYPE
{
	Unknown,
	Bootmgr,	// Unsupported
	WinloadExe,	// Unsupported
	BootmgfwEfi,
	BootmgrEfi,
	WinloadEfi,
	Ntoskrnl
} INPUT_FILETYPE;

typedef struct _CPUID
{
	int eax;
	int ebx;
	int ecx;
	int edx;
} CPUID, * PCPUID;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;	// 16
	LIST_ENTRY InMemoryOrderLinks;	// 32
	LIST_ENTRY InInitializationOrderLinks; // 48
	UINT64 ModuleBase; // 56
	UINT64 EntryPoint; // 64
	UINTN SizeOfImage; // 72
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY, **PPLDR_DATA_TABLE_ENTRY;

// taken from umap (btbd)
BOOLEAN CheckMask(CHAR8* base, CHAR8* pattern, CHAR8* mask);
VOID* FindPattern(CHAR8* base, UINTN size, CHAR8* pattern, CHAR8* mask);
VOID* GetExport(UINT8* ModuleBase, CHAR8* export);
VOID MemCopy(VOID* dest, VOID* src, UINTN size);
VOID* MemSet(VOID* dest, int val, UINT32 len);
int MemCmp(const void* s1, const void* s2, UINT32 n);
EFI_STATUS EFIAPI GetPeFileVersionInfo(IN CONST VOID* ImageBase, OUT UINT16* BuildNumber OPTIONAL, OUT UINT16* Revision OPTIONAL);