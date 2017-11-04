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
#include <asm/kvm_mmu.h>
#include <asm/kvm_nested_pv.h>

#include "sys_regs.h"

#include "trace.h"

typedef int (*pv_handle_fn)(struct kvm_vcpu *);

static u64 *get_special_reg(struct kvm_vcpu *vcpu, u32 sreg_num)
{
	switch (sreg_num) {
	case SP_EL1:
		return &vcpu->arch.ctxt.gp_regs.sp_el1;
	case ELR_EL1:
		return &vcpu->arch.ctxt.gp_regs.elr_el1;
	case SPSR_EL1:
		return &vcpu->arch.ctxt.gp_regs.spsr[KVM_SPSR_EL1];
	case SPSR_EL2_PV:
		return &vcpu_el2_sreg(vcpu, SPSR_EL2);
	case ELR_EL2_PV:
		return &vcpu_el2_sreg(vcpu, ELR_EL2);
	default:
		return ERR_PTR(-EINVAL);
	};
}

static u64* get_sys_regp(struct kvm_vcpu *vcpu, u16 imm)
{
	u32 sreg_num = get_sysreg_num(imm);
	u64 *sysregp;

	if (is_el2_reg(imm))
		sysregp = &vcpu->arch.ctxt.sys_regs[sreg_num];
	else if (sreg_num > NR_SYS_REGS) /* We keep sp_el1 in gp_regs */
		sysregp = get_special_reg(vcpu, sreg_num);
	else {	/* Otherwise, el1 sysregs are in sys_regs */
/*
		if (sreg_num != VBAR_EL1 && sreg_num != ELR_EL1 &&
		    sreg_num != SPSR_EL1) {
			kvm_err("PV access to [%d] el1 reg", sreg_num);
			BUG();
		}
*/
		sysregp = &vcpu->arch.ctxt.sys_regs[sreg_num];
	}

	return sysregp;
}

static u64* get_gp_regp(struct kvm_vcpu *vcpu, u16 imm)
{
	u32 gpreg_num = get_gpreg_num(imm);
	u64 *gpregp = &vcpu_gp_regs(vcpu)->regs.regs[gpreg_num];

	if (gpreg_num == 31)
		return NULL;
	return gpregp;
}

static int handle_mrs_pv(struct kvm_vcpu *vcpu)
{
	u16 imm = kvm_vcpu_hvc_get_imm(vcpu);
	u64 *gpregp = get_gp_regp(vcpu, imm);
	u64 *sysregp = get_sys_regp(vcpu, imm);

	if (IS_ERR(sysregp))
		return PTR_ERR(sysregp);

	trace_kvm_nested_mrs_pv(vcpu, get_sysreg_num(imm),
				*sysregp, get_gpreg_num(imm),
				is_el2_reg(imm));

	/* MRS doesn't take xzr(x31) as an operand, so gpregp is not NULL */
	*gpregp = *sysregp;
	return 1;
}

static int handle_msr_pv(struct kvm_vcpu *vcpu)
{
	u16 imm = kvm_vcpu_hvc_get_imm(vcpu);
	u64 *gpregp = get_gp_regp(vcpu, imm);
	u64 *sysregp = get_sys_regp(vcpu, imm);
	u64 val;
	int ret = 1;

	if (IS_ERR(sysregp))
		return PTR_ERR(sysregp);

	if (is_msr_imm(imm))
		val = get_msr_imm(imm);
	else if (gpregp)
		val = *gpregp;
	else
		val = 0;

	trace_kvm_nested_msr_pv(vcpu, get_sysreg_num(imm),
				val, get_gpreg_num(imm),
				is_el2_reg(imm));

	*sysregp = val;

	return ret;
}

static int handle_tlbi_pv(struct kvm_vcpu *vcpu)
{
	u16 imm = kvm_vcpu_hvc_get_imm(vcpu);

	kvm_err("Unknown PV encoding: imm: %#04x\n", imm);
	return -ENXIO;
}

/*
 * Emulate eret from virtual EL2.
 * See ARM ARM J8.1.4 AArch64.ExceptionReturn()
 */
static int handle_eret_pv(struct kvm_vcpu *vcpu)
{
	return kvm_handle_eret(vcpu, NULL);
}

static pv_handle_fn pv_handlers[] = {
	[MRS_PV]	= handle_mrs_pv,
	[MSR_IMM_PV]	= handle_msr_pv,
	[MSR_REG_PV]	= handle_msr_pv,
	[ERET_PV]	= handle_eret_pv,
	[TLBI_PV]	= handle_tlbi_pv,
};

static pv_handle_fn kvm_get_pv_handler(struct kvm_vcpu *vcpu)
{
	u16 imm = kvm_vcpu_hvc_get_imm(vcpu);
	u8 imm_instr = imm >> PV_INSTR_SHIFT;

	if (imm_instr >= ARRAY_SIZE(pv_handlers) || !pv_handlers[imm_instr]) {
		kvm_err("Unknown PV encoding: imm: %#04x\n", imm);
		return NULL;
	}

	return pv_handlers[imm_instr];
}

int handle_pv(struct kvm_vcpu *vcpu)
{
	pv_handle_fn pv_handler;

	pv_handler = kvm_get_pv_handler(vcpu);
	if (!pv_handler)
		return -ENXIO;

	return pv_handler(vcpu);
}

