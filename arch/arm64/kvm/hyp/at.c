/*
 * Copyright (C) 2017 - Linaro Ltd
 * Author: Jintack Lim <jintack.lim@linaro.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <asm/kvm_hyp.h>

static void __hyp_text __save_vmregs(struct kvm_cpu_context *ctxt)
{
	u64 *sys_regs = kern_hyp_va(ctxt->hw_sys_regs);

	sys_regs[TTBR0_EL1]     = read_sysreg_el1(ttbr0);
	sys_regs[TTBR1_EL1]     = read_sysreg_el1(ttbr1);
	sys_regs[TCR_EL1]       = read_sysreg_el1(tcr);
	sys_regs[SCTLR_EL1]     = read_sysreg_el1(sctlr);
}

static void __hyp_text __restore_vmregs(struct kvm_cpu_context *ctxt)
{
	u64 *sys_regs = kern_hyp_va(ctxt->hw_sys_regs);

	write_sysreg_el1(sys_regs[TTBR0_EL1],   ttbr0);
	write_sysreg_el1(sys_regs[TTBR1_EL1],   ttbr1);
	write_sysreg_el1(sys_regs[TCR_EL1],     tcr);
	write_sysreg_el1(sys_regs[SCTLR_EL1],   sctlr);
}

void __hyp_text __at_switch_to_guest_nvhe(struct kvm_vcpu *vcpu,
					  bool el2_regime)
{
	struct kvm_cpu_context *host_ctxt;
	struct kvm_cpu_context *guest_ctxt;
	u64 val;

	host_ctxt = kern_hyp_va(vcpu->arch.host_cpu_context);
	guest_ctxt = &vcpu->arch.ctxt;

	__save_vmregs(host_ctxt);
	__restore_vmregs(guest_ctxt);

	val = read_sysreg(hcr_el2);
	if (el2_regime)
		val |= (HCR_NV | HCR_NV1);
	write_sysreg(val, hcr_el2);
}

void __hyp_text __at_switch_to_guest_vhe(struct kvm_vcpu *vcpu, bool el2_regime)
{
	struct kvm_cpu_context *guest_ctxt = &vcpu->arch.ctxt;
	u64 val;

	__restore_vmregs(guest_ctxt);

	val = read_sysreg(hcr_el2);
	val &= ~HCR_TGE;
	if (el2_regime)
		val |= (HCR_NV | HCR_NV1);
	write_sysreg(val, hcr_el2);
}

/*
 * Switching to guest.
 *
 * 1. [nvhe] Save host vm regs
 * 2. [both] Restore guest vm regs
 * 3. [both] Set HCR_EL2.NV/NV1 bit if necessary
 * 4. [vhe]  Clear HCR_EL2.TGE
 */
static hyp_alternate_select(__at_switch_to_guest,
			    __at_switch_to_guest_nvhe, __at_switch_to_guest_vhe,
			    ARM64_HAS_VIRT_HOST_EXTN);

void __hyp_text __kvm_at_insn(struct kvm_vcpu *vcpu, unsigned long vaddr,
			      bool el2_regime, int sys_encoding)
{
	struct kvm_cpu_context *ctxt = &vcpu->arch.ctxt;
	struct kvm_cpu_context *host_ctxt;

	host_ctxt = kern_hyp_va(vcpu->arch.host_cpu_context);

	__at_switch_to_guest()(vcpu, el2_regime);

	switch (sys_encoding) {
	case AT_S1E1R:
	case AT_S1E2R:
		asm volatile("at s1e1r, %0" : : "r" (vaddr));
		break;
	case AT_S1E1W:
	case AT_S1E2W:
		asm volatile("at s1e1w, %0" : : "r" (vaddr));
		break;
	case AT_S1E0R:
		asm volatile("at s1e0r, %0" : : "r" (vaddr));
		break;
	case AT_S1E0W:
		asm volatile("at s1e0w, %0" : : "r" (vaddr));
		break;
	case AT_S1E1RP:
		asm volatile("at s1e1rp, %0" : : "r" (vaddr));
		break;
	case AT_S1E1WP:
		asm volatile("at s1e1wp, %0" : : "r" (vaddr));
		break;
	default:
		break;
	}

	/* Save the translation result to the virtual machine's context */
	ctxt->sys_regs[PAR_EL1] = read_sysreg(par_el1);

	/* Switch to the host */
	if (has_vhe()) {
		write_sysreg(HCR_HOST_VHE_FLAGS, hcr_el2);
	} else {
		/* We don't save guest vm regs; we didn't make any changes */
		__restore_vmregs(host_ctxt);
		write_sysreg(HCR_RW, hcr_el2);
	}
}
