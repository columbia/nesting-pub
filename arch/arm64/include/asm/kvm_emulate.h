/*
 * Copyright (C) 2012,2013 - ARM Ltd
 * Author: Marc Zyngier <marc.zyngier@arm.com>
 *
 * Derived from arch/arm/include/kvm_emulate.h
 * Copyright (C) 2012 - Virtual Open Systems and Columbia University
 * Author: Christoffer Dall <c.dall@virtualopensystems.com>
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

#ifndef __ARM64_KVM_EMULATE_H__
#define __ARM64_KVM_EMULATE_H__

#include <linux/kvm_host.h>

#include <asm/esr.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_mmio.h>
#include <asm/ptrace.h>
#include <asm/cputype.h>
#include <asm/virt.h>

#define CURRENT_EL_SP_EL0_VECTOR	0x0
#define CURRENT_EL_SP_ELx_VECTOR	0x200
#define LOWER_EL_AArch64_VECTOR		0x400
#define LOWER_EL_AArch32_VECTOR		0x600

enum exception_type {
	except_type_sync	= 0,
	except_type_irq		= 0x80,
	except_type_fiq		= 0x100,
	except_type_serror	= 0x180,
};

unsigned long *vcpu_reg32(const struct kvm_vcpu *vcpu, u8 reg_num);
unsigned long *vcpu_spsr32(const struct kvm_vcpu *vcpu);

bool kvm_condition_valid32(const struct kvm_vcpu *vcpu);
void kvm_skip_instr32(struct kvm_vcpu *vcpu, bool is_wide_instr);

void kvm_inject_undefined(struct kvm_vcpu *vcpu);
void kvm_inject_vabt(struct kvm_vcpu *vcpu);
void kvm_inject_dabt(struct kvm_vcpu *vcpu, unsigned long addr);
void kvm_inject_pabt(struct kvm_vcpu *vcpu, unsigned long addr);

int kvm_inject_nested_sync(struct kvm_vcpu *vcpu, u64 esr_el2);
int kvm_inject_nested_irq(struct kvm_vcpu *vcpu);

void kvm_arm_setup_shadow_state(struct kvm_vcpu *vcpu);
void kvm_arm_restore_shadow_state(struct kvm_vcpu *vcpu);
void kvm_arm_init_cpu_context(kvm_cpu_context_t *cpu_ctxt);
u64 cptr_to_cpacr(u64 cptr_el2);
u64 cpacr_to_cptr(u64 cpacr_el1);

static inline void vcpu_reset_hcr(struct kvm_vcpu *vcpu)
{
	vcpu->arch.hcr_el2 = HCR_GUEST_FLAGS;
	if (is_kernel_in_hyp_mode())
		vcpu->arch.hcr_el2 |= HCR_E2H;
	if (test_bit(KVM_ARM_VCPU_EL1_32BIT, vcpu->arch.features))
		vcpu->arch.hcr_el2 &= ~HCR_RW;
}

static inline unsigned long vcpu_get_hcr(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.hcr_el2;
}

static inline void vcpu_set_hcr(struct kvm_vcpu *vcpu, unsigned long hcr)
{
	vcpu->arch.hcr_el2 = hcr;
}

static inline unsigned long *vcpu_pc(const struct kvm_vcpu *vcpu)
{
	return (unsigned long *)&vcpu_gp_regs(vcpu)->regs.pc;
}

static inline unsigned long *vcpu_elr_el1(const struct kvm_vcpu *vcpu)
{
	return (unsigned long *)&vcpu_gp_regs(vcpu)->elr_el1;
}

static inline unsigned long *vcpu_cpsr(const struct kvm_vcpu *vcpu)
{
	return (unsigned long *)&vcpu_gp_regs(vcpu)->regs.pstate;
}

static inline bool vcpu_mode_is_32bit(const struct kvm_vcpu *vcpu)
{
	return !!(*vcpu_cpsr(vcpu) & PSR_MODE32_BIT);
}

static inline bool kvm_condition_valid(const struct kvm_vcpu *vcpu)
{
	if (vcpu_mode_is_32bit(vcpu))
		return kvm_condition_valid32(vcpu);

	return true;
}

static inline void kvm_skip_instr(struct kvm_vcpu *vcpu, bool is_wide_instr)
{
	if (vcpu_mode_is_32bit(vcpu))
		kvm_skip_instr32(vcpu, is_wide_instr);
	else
		*vcpu_pc(vcpu) += 4;
}

static inline void vcpu_set_thumb(struct kvm_vcpu *vcpu)
{
	*vcpu_cpsr(vcpu) |= COMPAT_PSR_T_BIT;
}

/*
 * vcpu_get_reg and vcpu_set_reg should always be passed a register number
 * coming from a read of ESR_EL2. Otherwise, it may give the wrong result on
 * AArch32 with banked registers.
 */
static inline unsigned long vcpu_get_reg(const struct kvm_vcpu *vcpu,
					 u8 reg_num)
{
	return (reg_num == 31) ? 0 : vcpu_gp_regs(vcpu)->regs.regs[reg_num];
}

static inline void vcpu_set_reg(struct kvm_vcpu *vcpu, u8 reg_num,
				unsigned long val)
{
	if (reg_num != 31)
		vcpu_gp_regs(vcpu)->regs.regs[reg_num] = val;
}

/* Get vcpu SPSR for current mode */
static inline unsigned long *vcpu_spsr(const struct kvm_vcpu *vcpu)
{
	if (vcpu_mode_is_32bit(vcpu))
		return vcpu_spsr32(vcpu);

	return (unsigned long *)&vcpu_gp_regs(vcpu)->spsr[KVM_SPSR_EL1];
}

static inline bool vcpu_mode_priv(const struct kvm_vcpu *vcpu)
{
	u32 mode;

	if (vcpu_mode_is_32bit(vcpu)) {
		mode = *vcpu_cpsr(vcpu) & COMPAT_PSR_MODE_MASK;
		return mode > COMPAT_PSR_MODE_USR;
	}

	mode = *vcpu_cpsr(vcpu) & PSR_MODE_MASK;

	return mode != PSR_MODE_EL0t;
}

static inline bool vcpu_mode_el2(const struct kvm_vcpu *vcpu)
{
	u32 mode;

	if (vcpu_mode_is_32bit(vcpu))
		return false;

	mode = *vcpu_cpsr(vcpu) & PSR_MODE_MASK;

	return mode == PSR_MODE_EL2h || mode == PSR_MODE_EL2t;
}

static inline bool vcpu_el2_imo_is_set(const struct kvm_vcpu *vcpu)
{
	return (vcpu_sys_reg(vcpu, HCR_EL2) & HCR_IMO);
}

static inline bool vcpu_el2_e2h_is_set(const struct kvm_vcpu *vcpu)
{
	return (vcpu_sys_reg(vcpu, HCR_EL2) & HCR_E2H);
}

static inline bool vcpu_el2_tge_is_set(const struct kvm_vcpu *vcpu)
{
	return (vcpu_sys_reg(vcpu, HCR_EL2) & HCR_TGE);
}


/*
 * When the NV and NV1 bits are set, the EL2 page table format is used for the
 * EL1 translation regime.
 */
static inline bool vcpu_el2_format_used(const struct kvm_vcpu *vcpu)
{
	return ((vcpu_sys_reg(vcpu, HCR_EL2) & HCR_NV) &&
		(vcpu_sys_reg(vcpu, HCR_EL2) & HCR_NV1));
}

static inline bool is_hyp_ctxt(const struct kvm_vcpu *vcpu)
{
	/*
	 * We are in a hypervisor context if the vcpu mode is EL2 or
	 * E2H and TGE bits are set. The latter means we are in the user space
	 * of the VHE kernel. ARMv8.1 ARM describes this as 'InHost'
	 */
	if (vcpu_mode_el2(vcpu) ||
	    (vcpu_el2_e2h_is_set(vcpu) && vcpu_el2_tge_is_set(vcpu)))
		return true;

	return false;
}

static inline bool vcpu_nested_stage2_enabled(const struct kvm_vcpu *vcpu)
{
	return (vcpu_sys_reg(vcpu, HCR_EL2) & HCR_VM);
}

static inline u32 kvm_vcpu_get_hsr(const struct kvm_vcpu *vcpu)
{
	return vcpu->arch.fault.esr_el2;
}

static inline int kvm_vcpu_get_condition(const struct kvm_vcpu *vcpu)
{
	u32 esr = kvm_vcpu_get_hsr(vcpu);

	if (esr & ESR_ELx_CV)
		return (esr & ESR_ELx_COND_MASK) >> ESR_ELx_COND_SHIFT;

	return -1;
}

static inline unsigned long kvm_vcpu_get_hfar(const struct kvm_vcpu *vcpu)
{
	return vcpu->arch.fault.far_el2;
}

static inline phys_addr_t kvm_vcpu_get_fault_ipa(const struct kvm_vcpu *vcpu)
{
	return ((phys_addr_t)vcpu->arch.fault.hpfar_el2 & HPFAR_MASK) << 8;
}

static inline u32 kvm_vcpu_hvc_get_imm(const struct kvm_vcpu *vcpu)
{
	return kvm_vcpu_get_hsr(vcpu) & ESR_ELx_xVC_IMM_MASK;
}

static inline bool kvm_vcpu_dabt_isvalid(const struct kvm_vcpu *vcpu)
{
	return !!(kvm_vcpu_get_hsr(vcpu) & ESR_ELx_ISV);
}

static inline bool kvm_vcpu_dabt_issext(const struct kvm_vcpu *vcpu)
{
	return !!(kvm_vcpu_get_hsr(vcpu) & ESR_ELx_SSE);
}

static inline int kvm_vcpu_dabt_get_rd(const struct kvm_vcpu *vcpu)
{
	return (kvm_vcpu_get_hsr(vcpu) & ESR_ELx_SRT_MASK) >> ESR_ELx_SRT_SHIFT;
}

static inline bool kvm_vcpu_dabt_isextabt(const struct kvm_vcpu *vcpu)
{
	return !!(kvm_vcpu_get_hsr(vcpu) & ESR_ELx_EA);
}

static inline bool kvm_vcpu_dabt_iss1tw(const struct kvm_vcpu *vcpu)
{
	return !!(kvm_vcpu_get_hsr(vcpu) & ESR_ELx_S1PTW);
}

static inline bool kvm_vcpu_dabt_iswrite(const struct kvm_vcpu *vcpu)
{
	return !!(kvm_vcpu_get_hsr(vcpu) & ESR_ELx_WNR) ||
		kvm_vcpu_dabt_iss1tw(vcpu); /* AF/DBM update */
}

static inline bool kvm_vcpu_dabt_is_cm(const struct kvm_vcpu *vcpu)
{
	return !!(kvm_vcpu_get_hsr(vcpu) & ESR_ELx_CM);
}

static inline int kvm_vcpu_dabt_get_as(const struct kvm_vcpu *vcpu)
{
	return 1 << ((kvm_vcpu_get_hsr(vcpu) & ESR_ELx_SAS) >> ESR_ELx_SAS_SHIFT);
}

/* This one is not specific to Data Abort */
static inline bool kvm_vcpu_trap_il_is32bit(const struct kvm_vcpu *vcpu)
{
	return !!(kvm_vcpu_get_hsr(vcpu) & ESR_ELx_IL);
}

static inline u8 kvm_vcpu_trap_get_class(const struct kvm_vcpu *vcpu)
{
	return ESR_ELx_EC(kvm_vcpu_get_hsr(vcpu));
}

static inline bool kvm_vcpu_trap_is_iabt(const struct kvm_vcpu *vcpu)
{
	return kvm_vcpu_trap_get_class(vcpu) == ESR_ELx_EC_IABT_LOW;
}

static inline u8 kvm_vcpu_trap_get_fault(const struct kvm_vcpu *vcpu)
{
	return kvm_vcpu_get_hsr(vcpu) & ESR_ELx_FSC;
}

static inline u8 kvm_vcpu_trap_get_fault_type(const struct kvm_vcpu *vcpu)
{
	return kvm_vcpu_get_hsr(vcpu) & ESR_ELx_FSC_TYPE;
}

static inline int kvm_vcpu_sys_get_rt(struct kvm_vcpu *vcpu)
{
	u32 esr = kvm_vcpu_get_hsr(vcpu);
	return (esr & ESR_ELx_SYS64_ISS_RT_MASK) >> ESR_ELx_SYS64_ISS_RT_SHIFT;
}

static inline bool kvm_is_write_fault(struct kvm_vcpu *vcpu)
{
	if (kvm_vcpu_trap_is_iabt(vcpu))
		return false;

	return kvm_vcpu_dabt_iswrite(vcpu);
}

static inline unsigned long kvm_vcpu_get_mpidr_aff(struct kvm_vcpu *vcpu)
{
	return vcpu_sys_reg(vcpu, MPIDR_EL1) & MPIDR_HWID_BITMASK;
}

static inline void kvm_vcpu_set_be(struct kvm_vcpu *vcpu)
{
	if (vcpu_mode_is_32bit(vcpu))
		*vcpu_cpsr(vcpu) |= COMPAT_PSR_E_BIT;
	else
		vcpu_sys_reg(vcpu, SCTLR_EL1) |= (1 << 25);
}

static inline bool kvm_vcpu_is_be(struct kvm_vcpu *vcpu)
{
	if (vcpu_mode_is_32bit(vcpu))
		return !!(*vcpu_cpsr(vcpu) & COMPAT_PSR_E_BIT);

	return !!(vcpu_sys_reg(vcpu, SCTLR_EL1) & (1 << 25));
}

static inline unsigned long vcpu_data_guest_to_host(struct kvm_vcpu *vcpu,
						    unsigned long data,
						    unsigned int len)
{
	if (kvm_vcpu_is_be(vcpu)) {
		switch (len) {
		case 1:
			return data & 0xff;
		case 2:
			return be16_to_cpu(data & 0xffff);
		case 4:
			return be32_to_cpu(data & 0xffffffff);
		default:
			return be64_to_cpu(data);
		}
	} else {
		switch (len) {
		case 1:
			return data & 0xff;
		case 2:
			return le16_to_cpu(data & 0xffff);
		case 4:
			return le32_to_cpu(data & 0xffffffff);
		default:
			return le64_to_cpu(data);
		}
	}

	return data;		/* Leave LE untouched */
}

static inline unsigned long vcpu_data_host_to_guest(struct kvm_vcpu *vcpu,
						    unsigned long data,
						    unsigned int len)
{
	if (kvm_vcpu_is_be(vcpu)) {
		switch (len) {
		case 1:
			return data & 0xff;
		case 2:
			return cpu_to_be16(data & 0xffff);
		case 4:
			return cpu_to_be32(data & 0xffffffff);
		default:
			return cpu_to_be64(data);
		}
	} else {
		switch (len) {
		case 1:
			return data & 0xff;
		case 2:
			return cpu_to_le16(data & 0xffff);
		case 4:
			return cpu_to_le32(data & 0xffffffff);
		default:
			return cpu_to_le64(data);
		}
	}

	return data;		/* Leave LE untouched */
}

static inline bool kvm_is_shadow_s2_fault(struct kvm_vcpu *vcpu)
{
	return vcpu_nested_stage2_enabled(vcpu) && !is_hyp_ctxt(vcpu);
}

#endif /* __ARM64_KVM_EMULATE_H__ */
