#pragma once

#define INTEL_VMEXIT_HANDLER_SIG "\x65\xC6\x04\x25\x6D\x00\x00\x00\x00\x48\x8B\x4C\x24\x00\x48\x8B\x54\x24\x00\xE8\x00\x00\x00\x00\xE9" // 65 C6 04 25 6D ?? ?? ?? ?? 48 8B 4C 24 ?? 48 8B 54 24 ?? E8 ?? ?? ?? ?? E9
#define INTEL_VMEXIT_HANDLER_MASK "xxxxxxxxxxxxx?xxxx?x????x"

#define AMD_VMEXIT_HANDLER_SIG "\xE8\x00\x00\x00\x00\x48\x89\x04\x24\xE9"
#define AMD_VMEXIT_HANDLER_MASK "x????xxxxx"

#pragma pack(push, 1)
typedef struct _VOYAGER_T
{
	UINT64 VmExitHandlerRva;
	UINT64 HypervModuleBase;
	UINT64 HypervModuleSize;
	UINT64 ModuleBase;
	UINT64 ModuleSize;

	//UINT64 offset_vmcb_base;
	//UINT64 offset_vmcb_link;
	//UINT64 offset_vmcb;
} VOYAGER_T, * PVOYAGER_T;
#pragma pack(pop)



VOID* MapModule(PVOYAGER_T VoyagerData, UINT8* ImageBase);
VOID MakeVoyagerData(PVOYAGER_T VoyagerData, VOID* HypervAlloc, UINT64 HypervAllocSize, VOID* PayLoadBase, UINT64 PayLoadSize);
VOID* HookVmExit(VOID* HypervBase, VOID* HypervSize, VOID* VmExitHook);

