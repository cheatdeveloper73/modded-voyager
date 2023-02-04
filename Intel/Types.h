#pragma once
#include <intrin.h>
#include <xmmintrin.h>
#include <cstddef>

#include <Windows.h>
#include <ntstatus.h>
#include "ia32.hpp"

//#define VMEXIT_KEY 0xAECFB5EFDEDD1EF // Launcher
//#define VMEXIT_KEY 0xEACFABEFDED84EB // Добрый
//#define VMEXIT_KEY 0xE5BFBAE8DED68EA //
//#define VMEXIT_KEY 0x86AD31E6DAD68B1 //Ibra
//#define VMEXIT_KEY 0x1FA981E6DFD6B52 //Dima Klim
//#define VMEXIT_KEY 0xBAEFA0EFDFA8485 // MaxMen
#define VMEXIT_KEY 0xBACFB55FDEAD180
//#define VMEXIT_KEY 0xEA8FC9EACFB8568 // михалыч
//#define VMEXIT_KEY 0xAECFB5EFDEDD1EF // Aman


#define PAGE_4KB 0x1000
#define PAGE_2MB PAGE_4KB * 512
#define PAGE_1GB PAGE_2MB * 512
#define VMX_EXIT_REASON_EXECUTE_VMCALL   0x00000012

using u8 = unsigned char;
using u16 = unsigned short;
using u32 = unsigned int;
using u64 = unsigned long long;
using u128 = __m128;

using guest_virt_t = u64;
using guest_phys_t = u64;
using host_virt_t = u64;
using host_phys_t = u64;

enum class vmexit_command_t
{
	init_page_tables = 5,
	read_guest_phys,
	write_guest_phys,
	copy_guest_virt,
	get_dirbase,
	translate,
	status,
};

enum class vmxroot_error_t
{
	error_success,
	pml4e_not_present,
	pdpte_not_present,
	pde_not_present,
	pte_not_present,
	vmxroot_translate_failure,
	invalid_self_ref_pml4e,
	invalid_mapping_pml4e,
	invalid_host_virtual,
	invalid_guest_physical,
	invalid_guest_virtual,
	page_table_init_failed
};

typedef struct _context_t
{
	u64 rax;
	u64 rcx;
	u64 rdx;
	u64 rbx;
	u64 rsp;
	u64 rbp;
	u64 rsi;
	u64 rdi;
	u64 r8;
	u64 r9;
	u64 r10;
	u64 r11;
	u64 r12;
	u64 r13;
	u64 r14;
	u64 r15;
	u128 xmm0;
	u128 xmm1;
	u128 xmm2;
	u128 xmm3;
	u128 xmm4;
	u128 xmm5;
} context_t, *pcontext_t;


using vmexit_handler_t = void (__fastcall*)(pcontext_t* context, void* unknown);

//using vmexit_handler_t = void(__fastcall*)(pcontext_t context, void* unknown);

#pragma pack(push, 1)
typedef struct _voyager_t
{
    u64 vmexit_handler_rva;
    u64 hyperv_module_base;
    u64 hyperv_module_size;
    u64 payload_base;
    u64 payload_size;
} voyager_t, *pvoyager_t;
#pragma pack(pop)

inline voyager_t GuardContext;