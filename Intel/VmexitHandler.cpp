#include "Mem.h"

#define ClearFlag(_F,_SF)               ((_F) &= ~(_SF))

static u64 GlobalKeyData = VMEXIT_KEY;

BOOLEAN IsGuestUserMode()
{
	VMX_SEGMENT_ACCESS_RIGHTS accessRight{};
	__vmx_vmread(VMCS_GUEST_SS_ACCESS_RIGHTS, (size_t*)&accessRight);
	return (accessRight.DescriptorPrivilegeLevel == 3);
}

void VmexitHandler(pcontext_t* context, void* unknown)
//void vmexit_handler(pcontext_t context, void* unknown)
{
	pcontext_t guest_registers = *context;
	//pcontext_t guest_registers = context;
	size_t vmexit_reason;
	__vmx_vmread(VMCS_EXIT_REASON, &vmexit_reason); 

	if (vmexit_reason == VMX_EXIT_REASON_EXECUTE_CPUID)
	{
		if (guest_registers->rcx == 0x12C11B554E4788C)
		{
			if (IsGuestUserMode())
			{
				if (guest_registers->rdx == 0x558402)
				{
					GlobalKeyData = guest_registers->r12;
					goto exit;
				}
			}
		}
		else if (guest_registers->rcx == GlobalKeyData)
		{
			switch ((vmexit_command_t)guest_registers->rdx)
			{
			case vmexit_command_t::init_page_tables:
			{
				guest_registers->rax = (u64)mm::init();	
				break;
			}
			case vmexit_command_t::get_dirbase:
			{
				u64 guest_dirbase = 0;
				__vmx_vmread(VMCS_GUEST_CR3, &guest_dirbase);
				if (guest_dirbase != 0)
				{
					guest_registers->r12 = cr3{ guest_dirbase }.pml4_pfn << 12;
					guest_registers->rax = (u64)vmxroot_error_t::error_success;
				}
				break;
			}
			case vmexit_command_t::read_guest_phys:
			{
				u64 guest_dirbase = 0;
				__vmx_vmread(VMCS_GUEST_CR3, &guest_dirbase);
				if (guest_dirbase != 0)
				{
					guest_dirbase = cr3{ guest_dirbase }.pml4_pfn << 12;
					guest_registers->rax = (u64)mm::read_guest_phys(guest_dirbase, guest_registers->r12, guest_registers->r8, guest_registers->r9);
				}
				break;
			}
			case vmexit_command_t::write_guest_phys:
			{
				u64 guest_dirbase = 0;
				__vmx_vmread(VMCS_GUEST_CR3, &guest_dirbase);
				if (guest_dirbase != 0)
				{
					guest_dirbase = cr3{ guest_dirbase }.pml4_pfn << 12;
					guest_registers->rax = (u64)mm::write_guest_phys(guest_dirbase, guest_registers->r12, guest_registers->r8, guest_registers->r9);
				}
				break;
			}
			case vmexit_command_t::copy_guest_virt:
			{
				guest_registers->rax = (u64)mm::copy_guest_virt(guest_registers->r12, guest_registers->r8, guest_registers->r9, guest_registers->r10, guest_registers->r11);
				break;
			}
			case vmexit_command_t::translate:
			{
				u64 guest_dirbase = cr3{ guest_registers->r12 }.pml4_pfn << 12;
				guest_registers->r9 = mm::translate_guest_virtual(guest_dirbase, guest_registers->r8);
				guest_registers->rax = (u64)vmxroot_error_t::error_success;
				break;
			}
			case vmexit_command_t::status: 
			{
				guest_registers->rax = (u64)vmxroot_error_t::error_success;
				break;
			}
			default:
				break;
			}
exit:
			size_t rip, exec_len;
			__vmx_vmread(VMCS_GUEST_RIP, &rip);
			__vmx_vmread(VMCS_VMEXIT_INSTRUCTION_LENGTH, &exec_len);
			__vmx_vmwrite(VMCS_GUEST_RIP, rip + exec_len);
			return;
		}
	}
	reinterpret_cast<vmexit_handler_t>( reinterpret_cast<u64>(&VmexitHandler) - GuardContext.vmexit_handler_rva)(context, unknown);
}