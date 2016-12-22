/*
 * Copyright (C) 2016 - Columbia University
 * Author: Jintack Lim <jintack@cs.columbia.edu>
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

#define	EL2_EXCEPT_SYNC_OFFSET	0x400
#define	EL2_EXCEPT_ASYNC_OFFSET	0x480


/*
 *  Emulate taking an exception. See ARM ARM J8.1.2 AArch64.TakeException()
 */
static int kvm_inject_nested(struct kvm_vcpu *vcpu, u64 esr_el2,
			     int exception_offset)
{
	int ret = 1;
	kvm_cpu_context_t *ctxt = &vcpu->arch.ctxt;

	/* We don't inject an exception recursively to virtual EL2 */
	if (vcpu_mode_el2(vcpu))
		BUG();

	ctxt->el2_regs[SPSR_EL2] = *vcpu_cpsr(vcpu);
	ctxt->el2_regs[ELR_EL2] = *vcpu_pc(vcpu);
	ctxt->el2_regs[ESR_EL2] = esr_el2;

	/* On an exception, PSTATE.SP = 1 */
	*vcpu_cpsr(vcpu) = PSR_MODE_EL2h;
	*vcpu_cpsr(vcpu) |=  (PSR_A_BIT | PSR_F_BIT | PSR_I_BIT | PSR_D_BIT);
	*vcpu_pc(vcpu) = ctxt->el2_regs[VBAR_EL2] + exception_offset;

	trace_kvm_inject_nested_exception(vcpu, esr_el2, *vcpu_pc(vcpu));

	return ret;
}

int kvm_inject_nested_sync(struct kvm_vcpu *vcpu, u64 esr_el2)
{
	return kvm_inject_nested(vcpu, esr_el2, EL2_EXCEPT_SYNC_OFFSET);
}

int kvm_inject_nested_irq(struct kvm_vcpu *vcpu)
{
	u64 esr_el2 = kvm_vcpu_get_hsr(vcpu);
	/* We supports only IRQ and FIQ, so the esr_el2 is not updated. */
	return kvm_inject_nested(vcpu, esr_el2, EL2_EXCEPT_ASYNC_OFFSET);
}
