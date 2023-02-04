#include "Types.h"
#include "Mem.h"

static u64 GlobalKeyData = VMEXIT_KEY;

auto VmexitHandler(void* unknown, svm::pguest_context context) -> svm::pgs_base_struct
{
	const auto vmcb = svm::get_vmcb();

	if (vmcb->exitcode == VMEXIT_CPUID)
	{
		if (context->rcx == 0x12C11B554E4788C)
		{
			if (vmcb->cpl == 3)
			{
				if (context->rdx == 0x558402)
				{
					GlobalKeyData = context->r12;
					goto exit;
				}
			}
		}
		else if (context->rcx == GlobalKeyData)
		{
			switch ((svm::vmexit_command_t)context->rdx)
			{
			case svm::vmexit_command_t::init_page_tables:
			{
				vmcb->rax = (u64)mm::init();
				break;
			}
			case svm::vmexit_command_t::get_dirbase:
			{
				context->r12 = cr3{ vmcb->cr3 }.pml4_pfn << 12;;
				vmcb->rax = (u64)svm::vmxroot_error_t::error_success;
				break;
			}
			case svm::vmexit_command_t::read_guest_phys:
			{
				const auto guest_dirbase = cr3{ vmcb->cr3 }.pml4_pfn << 12;
				vmcb->rax = (u64)mm::read_guest_phys(guest_dirbase, context->r12, context->r8, context->r9);
				break;
			}
			case svm::vmexit_command_t::write_guest_phys:
			{
				const auto guest_dirbase = cr3{ vmcb->cr3 }.pml4_pfn << 12;
				vmcb->rax = (u64)mm::write_guest_phys(guest_dirbase, context->r12, context->r8, context->r9);
				break;
			}
			case svm::vmexit_command_t::copy_guest_virt:
			{
				vmcb->rax = (u64)mm::copy_guest_virt(context->r12, context->r8, context->r9, context->r10, context->r11);
				break;
			}
			case svm::vmexit_command_t::translate:
			{
				const auto guest_dirbase = cr3{ vmcb->cr3 }.pml4_pfn << 12;
				context->r9 = mm::translate_guest_virtual(guest_dirbase, context->r8);
				vmcb->rax = (u64)svm::vmxroot_error_t::error_success;
				break;
			}
			case svm::vmexit_command_t::status:
			{
				vmcb->rax = (u64)svm::vmxroot_error_t::error_success;
				break;
			}
			default:
				break;
			}
		exit:
			vmcb->rip = vmcb->nrip;
			return reinterpret_cast<svm::pgs_base_struct>(__readgsqword(0));
		}
	}
	return reinterpret_cast<svm::vcpu_run_t>(reinterpret_cast<u64>(&VmexitHandler) - svm::GuardContext.vmexit_handler_rva)(unknown, context);
}