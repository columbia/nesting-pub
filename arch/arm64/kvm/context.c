/*
 * Copyright (C) 2016 - Linaro Ltd.
 * Author: Christoffer Dall <christoffer.dall@linaro.org>
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

#include <linux/kvm_host.h>
#include <asm/kvm_emulate.h>

/**
 * kvm_arm_setup_shadow_state -- prepare shadow state based on emulated mode
 * @vcpu: The VCPU pointer
 */
void kvm_arm_setup_shadow_state(struct kvm_vcpu *vcpu)
{
	struct kvm_cpu_context *ctxt = &vcpu->arch.ctxt;
	if (unlikely(vcpu_mode_el2(vcpu))) {
		ctxt->hw_pstate = *vcpu_cpsr(vcpu) & ~PSR_MODE_MASK;

		/*
		 * We emulate virtual EL2 mode in hardware EL1 mode using the
		 * same stack pointer mode as the guest expects.
		 */
		if ((*vcpu_cpsr(vcpu) & PSR_MODE_MASK) == PSR_MODE_EL2h)
			ctxt->hw_pstate |= PSR_MODE_EL1h;
		else
			ctxt->hw_pstate |= PSR_MODE_EL1t;

		ctxt->hw_sys_regs = ctxt->shadow_sys_regs;
		ctxt->hw_sp_el1 = ctxt->el2_regs[SP_EL2];
	} else {
		ctxt->hw_pstate = *vcpu_cpsr(vcpu);
		ctxt->hw_sys_regs = ctxt->sys_regs;
		ctxt->hw_sp_el1 = ctxt->gp_regs.sp_el1;
	}
}

/**
 * kvm_arm_restore_shadow_state -- write back shadow state from guest
 * @vcpu: The VCPU pointer
 */
void kvm_arm_restore_shadow_state(struct kvm_vcpu *vcpu)
{
	struct kvm_cpu_context *ctxt = &vcpu->arch.ctxt;
	if (unlikely(vcpu_mode_el2(vcpu))) {
		*vcpu_cpsr(vcpu) &= PSR_MODE_MASK;
		*vcpu_cpsr(vcpu) |= ctxt->hw_pstate & ~PSR_MODE_MASK;
		ctxt->el2_regs[SP_EL2] = ctxt->hw_sp_el1;
	} else {
		*vcpu_cpsr(vcpu) = ctxt->hw_pstate;
		ctxt->gp_regs.sp_el1 = ctxt->hw_sp_el1;
	}
}

void kvm_arm_init_cpu_context(kvm_cpu_context_t *cpu_ctxt)
{
	cpu_ctxt->hw_sys_regs = &cpu_ctxt->sys_regs[0];
}
