/*
 * Copyright (C) 2016 - Linaro and Columbia University
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

#include <linux/kvm.h>
#include <linux/kvm_host.h>

#include <asm/kvm_emulate.h>

#include "trace.h"

/* This is borrowed from get_except_vector in inject_fault.c */
static u64 get_el2_except_vector(struct kvm_vcpu *vcpu,
		enum exception_type type)
{
	u64 exc_offset;

	switch (*vcpu_cpsr(vcpu) & (PSR_MODE_MASK | PSR_MODE32_BIT)) {
	case PSR_MODE_EL2t:
		exc_offset = CURRENT_EL_SP_EL0_VECTOR;
		break;
	case PSR_MODE_EL2h:
		exc_offset = CURRENT_EL_SP_ELx_VECTOR;
		break;
	case PSR_MODE_EL1t:
	case PSR_MODE_EL1h:
	case PSR_MODE_EL0t:
		exc_offset = LOWER_EL_AArch64_VECTOR;
		break;
	default:
		kvm_err("Unexpected previous exception level: aarch32\n");
		exc_offset = LOWER_EL_AArch32_VECTOR;
	}

	return vcpu_sys_reg(vcpu, VBAR_EL2) + exc_offset + type;
}

/*
 * Emulate taking an exception to EL2.
 * See ARM ARM J8.1.2 AArch64.TakeException()
 */
static int kvm_inject_nested(struct kvm_vcpu *vcpu, u64 esr_el2,
			     enum exception_type type)
{
	int ret = 1;

	if (!nested_virt_in_use(vcpu)) {
		kvm_err("Unexpected call to %s for the non-nesting configuration\n",
				__func__);
		return -EINVAL;
	}

	vcpu_el2_sreg(vcpu, SPSR_EL2) = *vcpu_cpsr(vcpu);
	vcpu_el2_sreg(vcpu, ELR_EL2) = *vcpu_pc(vcpu);
	vcpu_sys_reg(vcpu, ESR_EL2) = esr_el2;

	*vcpu_pc(vcpu) = get_el2_except_vector(vcpu, type);
	/* On an exception, PSTATE.SP becomes 1 */
	*vcpu_cpsr(vcpu) = PSR_MODE_EL2h;
	*vcpu_cpsr(vcpu) |=  (PSR_A_BIT | PSR_F_BIT | PSR_I_BIT | PSR_D_BIT);

	trace_kvm_inject_nested_exception(vcpu, esr_el2, *vcpu_pc(vcpu));

	return ret;
}

int kvm_inject_nested_sync(struct kvm_vcpu *vcpu, u64 esr_el2)
{
	return kvm_inject_nested(vcpu, esr_el2, except_type_sync);
}

int kvm_inject_nested_irq(struct kvm_vcpu *vcpu)
{
	/*
	 * Do not inject an irq if the current exception level is EL2 and
	 * virtual HCR_EL2.IMO is set and IRQ mask is set.
	 * See Table D1-16 Physical interrupt masking when EL3 is not
	 * implemented and EL2 is implemented.
	 */
	if ((vcpu_sys_reg(vcpu, HCR_EL2) & HCR_IMO) && vcpu_mode_el2(vcpu)
	    && (*vcpu_cpsr(vcpu) & PSR_I_BIT))
		return 1;

	/* esr_el2 value doesn't matter for exits due to irqs. */
	return kvm_inject_nested(vcpu, 0, except_type_irq);
}
