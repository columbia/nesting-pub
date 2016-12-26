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
#include <asm/esr.h>
#include <asm/kvm_mmu.h>

struct el1_el2_map {
	enum vcpu_sysreg	el1;
	enum el2_regs		el2;
};

/*
 * List of EL2 registers which can be directly applied to EL1 registers to
 * emulate running EL2 in EL1.  The EL1 registers here must either be trapped
 * or paravirtualized in EL1.
 */
static const struct el1_el2_map el1_el2_map[] = {
	{ AMAIR_EL1, AMAIR_EL2 },
	{ MAIR_EL1, MAIR_EL2 },
	{ TTBR0_EL1, TTBR0_EL2 },
	{ ACTLR_EL1, ACTLR_EL2 },
	{ AFSR0_EL1, AFSR0_EL2 },
	{ AFSR1_EL1, AFSR1_EL2 },
	{ SCTLR_EL1, SCTLR_EL2 },
	{ VBAR_EL1, VBAR_EL2 },
};

static inline u64 tcr_el2_ips_to_tcr_el1_ps(u64 tcr_el2)
{
	return ((tcr_el2 & TCR_EL2_PS_MASK) >> TCR_EL2_PS_SHIFT)
		<< TCR_IPS_SHIFT;
}

static inline u64 cptr_el2_to_cpacr_el1(u64 cptr_el2)
{
	u64 cpacr_el1 = 0;

	if (!(cptr_el2 & CPTR_EL2_TFP))
		cpacr_el1 |= CPACR_EL1_FPEN;
	if (cptr_el2 & CPTR_EL2_TTA)
		cpacr_el1 |= CPACR_EL1_TTA;

	return cpacr_el1;
}

static void create_shadow_el1_sysregs(struct kvm_vcpu *vcpu)
{
	u64 *s_sys_regs = vcpu->arch.ctxt.shadow_sys_regs;
	u64 *el2_regs = vcpu->arch.ctxt.el2_regs;
	u64 tcr_el2;
	int i;

	for (i = 0; i < ARRAY_SIZE(el1_el2_map); i++) {
		const struct el1_el2_map *map = &el1_el2_map[i];

		s_sys_regs[map->el1] = el2_regs[map->el2];
	}

	tcr_el2 = el2_regs[TCR_EL2];
	s_sys_regs[TCR_EL1] =
		TCR_EPD1 |	/* disable TTBR1_EL1 */
		((tcr_el2 & TCR_EL2_TBI) ? TCR_TBI0 : 0) |
		tcr_el2_ips_to_tcr_el1_ps(tcr_el2) |
		(tcr_el2 & TCR_EL2_TG0_MASK) |
		(tcr_el2 & TCR_EL2_ORGN0_MASK) |
		(tcr_el2 & TCR_EL2_IRGN0_MASK) |
		(tcr_el2 & TCR_EL2_T0SZ_MASK);

	/* Rely on separate VMID for VA context, always use ASID 0 */
	s_sys_regs[TTBR0_EL1] &= ~GENMASK_ULL(63, 48);
	s_sys_regs[TTBR1_EL1] = 0;

	s_sys_regs[CPACR_EL1] = cptr_el2_to_cpacr_el1(el2_regs[CPTR_EL2]);
}

static void setup_s2_mmu(struct kvm_vcpu *vcpu)
{
	struct kvm_s2_mmu *mmu = &vcpu->kvm->arch.mmu;
	struct kvm_s2_vmid *vmid = vcpu_get_active_vmid(vcpu);

	vcpu->arch.hw_vttbr = kvm_get_vttbr(vmid, mmu);
	vcpu->arch.hw_mmu = mmu;
}

/*
 * List of EL1 registers which we allow the virtual EL2 mode to access
 * directly without trapping and which haven't been paravirtualized.
 *
 * Probably CNTKCTL_EL1 should not be copied but be accessed via trap. Because,
 * the guest hypervisor running in EL1 can be affected by event streams
 * configured via CNTKCTL_EL1, which it does not expect. We don't have a
 * mechanism to trap on CNTKCTL_EL1 as of now (v8.3), keep it in here instead.
 */
static const int el1_non_trap_regs[] = {
	CNTKCTL_EL1,
	CSSELR_EL1,
	PAR_EL1,
	TPIDR_EL0,
	TPIDR_EL1,
	TPIDRRO_EL0
};

/**
 * sync_shadow_el1_state - Going to/from the virtual EL2 state, sync state
 * @vcpu:	The VCPU pointer
 * @setup:	True, if on the way to the guest (called from setup)
 *		False, if returning form the guet (calld from restore)
 *
 * Some EL1 registers are accessed directly by the virtual EL2 mode because
 * they in no way affect execution state in virtual EL2.   However, we must
 * still ensure that virtual EL2 observes the same state of the EL1 registers
 * as the normal VM's EL1 mode, so copy this state as needed on setup/restore.
 */
static void sync_shadow_el1_state(struct kvm_vcpu *vcpu, bool setup)
{
	u64 *sys_regs = vcpu->arch.ctxt.sys_regs;
	u64 *s_sys_regs = vcpu->arch.ctxt.shadow_sys_regs;
	int i;

	for (i = 0; i < ARRAY_SIZE(el1_non_trap_regs); i++) {
		const int sr = el1_non_trap_regs[i];

		if (setup)
			s_sys_regs[sr] = sys_regs[sr];
		else
			sys_regs[sr] = s_sys_regs[sr];
	}
}

/**
 * kvm_arm_setup_shadow_state -- prepare shadow state based on emulated mode
 * @vcpu: The VCPU pointer
 */
void kvm_arm_setup_shadow_state(struct kvm_vcpu *vcpu)
{
	struct kvm_cpu_context *ctxt = &vcpu->arch.ctxt;

	vgic_handle_nested_maint_irq(vcpu);

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

		sync_shadow_el1_state(vcpu, true);
		create_shadow_el1_sysregs(vcpu);
		ctxt->hw_sys_regs = ctxt->shadow_sys_regs;
		ctxt->hw_sp_el1 = ctxt->el2_regs[SP_EL2];
	} else {
		ctxt->hw_pstate = *vcpu_cpsr(vcpu);
		ctxt->hw_sys_regs = ctxt->sys_regs;
		ctxt->hw_sp_el1 = ctxt->gp_regs.sp_el1;
	}

	vgic_v2_setup_shadow_state(vcpu);

	setup_s2_mmu(vcpu);
}

/**
 * kvm_arm_restore_shadow_state -- write back shadow state from guest
 * @vcpu: The VCPU pointer
 */
void kvm_arm_restore_shadow_state(struct kvm_vcpu *vcpu)
{
	struct kvm_cpu_context *ctxt = &vcpu->arch.ctxt;
	if (unlikely(vcpu_mode_el2(vcpu))) {
		sync_shadow_el1_state(vcpu, false);
		*vcpu_cpsr(vcpu) &= PSR_MODE_MASK;
		*vcpu_cpsr(vcpu) |= ctxt->hw_pstate & ~PSR_MODE_MASK;
		ctxt->el2_regs[SP_EL2] = ctxt->hw_sp_el1;
	} else {
		*vcpu_cpsr(vcpu) = ctxt->hw_pstate;
		ctxt->gp_regs.sp_el1 = ctxt->hw_sp_el1;
	}

	vgic_v2_restore_shadow_state(vcpu);
}

void kvm_arm_init_cpu_context(kvm_cpu_context_t *cpu_ctxt)
{
	cpu_ctxt->hw_sys_regs = &cpu_ctxt->sys_regs[0];
}
