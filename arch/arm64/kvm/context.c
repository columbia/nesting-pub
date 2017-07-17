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

static void flush_shadow_special_regs(struct kvm_vcpu *vcpu)
{
	struct kvm_cpu_context *ctxt = &vcpu->arch.ctxt;

	ctxt->hw_pstate = *vcpu_cpsr(vcpu) & ~PSR_MODE_MASK;
	/*
	 * We can emulate the guest's configuration of which
	 * stack pointer to use when executing in virtual EL2 by
	 * using the equivalent feature in EL1 to point to
	 * either the EL1 or EL0 stack pointer.
	 */
	if ((*vcpu_cpsr(vcpu) & PSR_MODE_MASK) == PSR_MODE_EL2h)
		ctxt->hw_pstate |= PSR_MODE_EL1h;
	else
		ctxt->hw_pstate |= PSR_MODE_EL1t;

	ctxt->hw_sys_regs = ctxt->shadow_sys_regs;
	ctxt->hw_sp_el1 = vcpu_el2_sreg(vcpu, SP_EL2);
	ctxt->hw_elr_el1 = vcpu_el2_sreg(vcpu, ELR_EL2);
	ctxt->hw_spsr_el1 = vcpu_el2_sreg(vcpu, SPSR_EL2);
}

static void flush_special_regs(struct kvm_vcpu *vcpu)
{
	struct kvm_cpu_context *ctxt = &vcpu->arch.ctxt;

	ctxt->hw_pstate = *vcpu_cpsr(vcpu);
	ctxt->hw_sys_regs = ctxt->sys_regs;
	ctxt->hw_sp_el1 = ctxt->gp_regs.sp_el1;
	ctxt->hw_elr_el1 = ctxt->gp_regs.elr_el1;
	ctxt->hw_spsr_el1 = ctxt->gp_regs.spsr[KVM_SPSR_EL1];
}

static void sync_shadow_special_regs(struct kvm_vcpu *vcpu)
{
	struct kvm_cpu_context *ctxt = &vcpu->arch.ctxt;

	*vcpu_cpsr(vcpu) &= PSR_MODE_MASK;
	*vcpu_cpsr(vcpu) |= ctxt->hw_pstate & ~PSR_MODE_MASK;
	vcpu_el2_sreg(vcpu, SP_EL2) = ctxt->hw_sp_el1;
	vcpu_el2_sreg(vcpu, ELR_EL2) = ctxt->hw_elr_el1;
	vcpu_el2_sreg(vcpu, SPSR_EL2) = ctxt->hw_spsr_el1;
}

static void sync_special_regs(struct kvm_vcpu *vcpu)
{
	struct kvm_cpu_context *ctxt = &vcpu->arch.ctxt;

	*vcpu_cpsr(vcpu) = ctxt->hw_pstate;
	ctxt->gp_regs.sp_el1 = ctxt->hw_sp_el1;
	ctxt->gp_regs.elr_el1 = ctxt->hw_elr_el1;
	ctxt->gp_regs.spsr[KVM_SPSR_EL1] = ctxt->hw_spsr_el1;
}

/**
 * kvm_arm_setup_shadow_state -- prepare shadow state based on emulated mode
 * @vcpu: The VCPU pointer
 */
void kvm_arm_setup_shadow_state(struct kvm_vcpu *vcpu)
{
	struct kvm_cpu_context *ctxt = &vcpu->arch.ctxt;

	if (unlikely(vcpu_mode_el2(vcpu))) {
		flush_shadow_special_regs(vcpu);
		ctxt->hw_sys_regs = ctxt->shadow_sys_regs;
	} else {
		flush_special_regs(vcpu);
		ctxt->hw_sys_regs = ctxt->sys_regs;
	}
}

/**
 * kvm_arm_restore_shadow_state -- write back shadow state from guest
 * @vcpu: The VCPU pointer
 */
void kvm_arm_restore_shadow_state(struct kvm_vcpu *vcpu)
{
	if (unlikely(vcpu_mode_el2(vcpu)))
		sync_shadow_special_regs(vcpu);
	else
		sync_special_regs(vcpu);
}

void kvm_arm_init_cpu_context(kvm_cpu_context_t *cpu_ctxt)
{
	/* This is to set hw_sys_regs of host_cpu_context */
	cpu_ctxt->hw_sys_regs = cpu_ctxt->sys_regs;
}
