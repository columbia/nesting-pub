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
	enum vcpu_sysreg	el2;
};

/*
 * List of EL2 registers which can be directly applied to EL1 registers to
 * emulate running EL2 in EL1.
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

/*
 * List of pair of EL1/EL2 registers which are used to access real EL2
 * registers in EL2 with E2H bit set.
 */
static const struct el1_el2_map vhe_map[] = {
	{ SCTLR_EL1, SCTLR_EL2 },
	{ CPACR_EL1, CPTR_EL2 },
	{ TTBR0_EL1, TTBR0_EL2 },
	{ TTBR1_EL1, TTBR1_EL2 },
	{ TCR_EL1, TCR_EL2},
	{ AFSR0_EL1, AFSR0_EL2 },
	{ AFSR1_EL1, AFSR1_EL2 },
	{ ESR_EL1, ESR_EL2},
	{ FAR_EL1, FAR_EL2},
	{ MAIR_EL1, MAIR_EL2 },
	{ AMAIR_EL1, AMAIR_EL2 },
	{ VBAR_EL1, VBAR_EL2 },
	{ CONTEXTIDR_EL1, CONTEXTIDR_EL2 },
	{ CNTKCTL_EL1, CNTHCTL_EL2 },
};

static inline u64 tcr_el2_ips_to_tcr_el1_ps(u64 tcr_el2)
{
	return ((tcr_el2 & TCR_EL2_PS_MASK) >> TCR_EL2_PS_SHIFT)
		<< TCR_IPS_SHIFT;
}

u64 cptr_to_cpacr(u64 cptr_el2)
{
	u64 cpacr_el1 = 0;

	if (!(cptr_el2 & CPTR_EL2_TFP))
		cpacr_el1 |= CPACR_EL1_FPEN;
	if (cptr_el2 & CPTR_EL2_TTA)
		cpacr_el1 |= CPACR_EL1_TTA;

	return cpacr_el1;
}

u64 cpacr_to_cptr(u64 cpacr_el1)
{
	u64 cptr_el2;

	cptr_el2 = CPTR_EL2_DEFAULT;
	if (!(cpacr_el1 & CPACR_EL1_FPEN))
		cptr_el2 |= CPTR_EL2_TFP;
	if (cpacr_el1 & CPACR_EL1_TTA)
		cptr_el2 |= CPTR_EL2_TTA;
	if (cpacr_el1 & CPTR_EL2_TCPAC)
		cptr_el2 |= CPTR_EL2_TCPAC;

	return cptr_el2;
}

static void sync_shadow_el1_sysregs(struct kvm_vcpu *vcpu)
{
	u64 *s_sys_regs = vcpu->arch.ctxt.shadow_sys_regs;
	int i;

	/*
	 * In the virtual EL2 without VHE no EL1 system registers can't be
	 * changed without trap except el1_non_trap_regs[]. So we have nothing
	 * to sync on exit from a guest.
	 */
	if (!vcpu_el2_e2h_is_set(vcpu))
		return;

	for (i = 0; i < ARRAY_SIZE(vhe_map); i++) {
		const struct el1_el2_map *map = &vhe_map[i];
		u64 *el2_reg = &vcpu_sys_reg(vcpu, map->el2);

		/* We do trap-and-emulate CPACR_EL1 accesses. So, don't sync */
		if (map->el2 == CPTR_EL2)
			continue;
		*el2_reg = s_sys_regs[map->el1];
	}
}

static void flush_shadow_el1_sysregs_nvhe(struct kvm_vcpu *vcpu)
{
	u64 *s_sys_regs = vcpu->arch.ctxt.shadow_sys_regs;
	u64 tcr_el2;
	int i;

	for (i = 0; i < ARRAY_SIZE(el1_el2_map); i++) {
		const struct el1_el2_map *map = &el1_el2_map[i];

		s_sys_regs[map->el1] = vcpu_sys_reg(vcpu, map->el2);
	}

	tcr_el2 = vcpu_sys_reg(vcpu, TCR_EL2);
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

	s_sys_regs[CPACR_EL1] = cptr_to_cpacr(vcpu_sys_reg(vcpu, CPTR_EL2));
}

static void flush_shadow_el1_sysregs_vhe(struct kvm_vcpu *vcpu)
{
	u64 *s_sys_regs = vcpu->arch.ctxt.shadow_sys_regs;
	int i;

	/*
	 * When e2h bit is set, EL2 registers becomes compatible
	 * with corrensponding EL1 registers. So, no conversion required.
	 */
	for (i = 0; i < ARRAY_SIZE(vhe_map); i++) {
		const struct el1_el2_map *map = &vhe_map[i];
		u64 *el1_reg = &s_sys_regs[map->el1];

		if (map->el2 == CPTR_EL2)
			*el1_reg = cptr_to_cpacr(vcpu_sys_reg(vcpu, map->el2));
		else
			*el1_reg = vcpu_sys_reg(vcpu, map->el2);
	}
}

static void flush_shadow_el1_sysregs(struct kvm_vcpu *vcpu)
{
	if (vcpu_el2_e2h_is_set(vcpu))
		flush_shadow_el1_sysregs_vhe(vcpu);
	else
		flush_shadow_el1_sysregs_nvhe(vcpu);
}

static void setup_s2_mmu(struct kvm_vcpu *vcpu)
{
	struct kvm_s2_mmu *mmu = vcpu_get_active_s2_mmu(vcpu);
	struct kvm_s2_vmid *vmid = vcpu_get_active_vmid(vcpu);

	vcpu->arch.hw_vttbr = kvm_get_vttbr(vmid, mmu);
	vcpu->arch.hw_mmu = mmu;
}

/*
 * List of EL0 and EL1 registers which we allow the virtual EL2 mode to access
 * directly without trapping. This is possible because the impact of
 * accessing those registers are the same regardless of the exception
 * levels that are allowed.
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
 * copy_shadow_non_trap_el1_state
 * @vcpu:      The VCPU pointer
 * @setup:     True, if on the way to the guest (called from setup)
 *             False, if returning form the guet (calld from restore)
 *
 * Some EL1 registers are accessed directly by the virtual EL2 mode because
 * they in no way affect execution state in virtual EL2.   However, we must
 * still ensure that virtual EL2 observes the same state of the EL1 registers
 * as the normal VM's EL1 mode, so copy this state as needed on setup/restore.
 */
static void copy_shadow_non_trap_el1_state(struct kvm_vcpu *vcpu, bool setup)
{
	u64 *s_sys_regs = vcpu->arch.ctxt.shadow_sys_regs;
	int i;

	for (i = 0; i < ARRAY_SIZE(el1_non_trap_regs); i++) {
		const int sr = el1_non_trap_regs[i];

		/*
		 * We trap on cntkctl_el12 accesses from virtual EL2 as suppose
		 * to not trapping on cntlctl_el1 accesses.
		 */
		if (vcpu_el2_e2h_is_set(vcpu) && sr == CNTKCTL_EL1)
			continue;

		if (setup)
			s_sys_regs[sr] = vcpu_sys_reg(vcpu, sr);
		else
			vcpu_sys_reg(vcpu, sr) = s_sys_regs[sr];
	}
}

static void sync_shadow_non_trap_el1_state(struct kvm_vcpu *vcpu)
{
	copy_shadow_non_trap_el1_state(vcpu, false);
}

static void flush_shadow_non_trap_el1_state(struct kvm_vcpu *vcpu)
{
	copy_shadow_non_trap_el1_state(vcpu, true);
}

static void flush_shadow_special_regs(struct kvm_vcpu *vcpu)
{
	struct kvm_cpu_context *ctxt = &vcpu->arch.ctxt;

	ctxt->hw_pstate = *vcpu_cpsr(vcpu) & ~PSR_MODE_MASK;
	if (vcpu_mode_el2(vcpu)) {
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
	}

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

	*vcpu_cpsr(vcpu) = ctxt->hw_pstate;
	*vcpu_cpsr(vcpu) &= ~PSR_MODE_MASK;
	/* Set vcpu exception level depending on the physical EL */
	if ((ctxt->hw_pstate & PSR_MODE_MASK) == PSR_MODE_EL0t)
		*vcpu_cpsr(vcpu) |= PSR_MODE_EL0t;
	else
		*vcpu_cpsr(vcpu) |= PSR_MODE_EL2h;

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

static void setup_mpidr_el1(struct kvm_vcpu *vcpu)
{
	/*
	 * A non-secure EL0 or EL1 read of MPIDR_EL1 returns
	 * the value of VMPIDR_EL2. For nested virtualization,
	 * it comes from the virtual VMPIDR_EL2.
	 */
	if (nested_virt_in_use(vcpu))
		vcpu_sys_reg(vcpu, MPIDR_EL1) = vcpu_sys_reg(vcpu, VMPIDR_EL2);
}

/**
 * kvm_arm_setup_shadow_state -- prepare shadow state based on emulated mode
 * @vcpu: The VCPU pointer
 */
void kvm_arm_setup_shadow_state(struct kvm_vcpu *vcpu)
{
	struct kvm_cpu_context *ctxt = &vcpu->arch.ctxt;

	vgic_handle_nested_maint_irq(vcpu);

	if (unlikely(is_hyp_ctxt(vcpu))) {
		flush_shadow_special_regs(vcpu);
		flush_shadow_el1_sysregs(vcpu);
		flush_shadow_non_trap_el1_state(vcpu);
		ctxt->hw_sys_regs = ctxt->shadow_sys_regs;
	} else {
		flush_special_regs(vcpu);
		setup_mpidr_el1(vcpu);
		ctxt->hw_sys_regs = ctxt->sys_regs;
	}

	setup_s2_mmu(vcpu);

	vgic_v2_setup_shadow_state(vcpu);
}

/**
 * kvm_arm_restore_shadow_state -- write back shadow state from guest
 * @vcpu: The VCPU pointer
 */
void kvm_arm_restore_shadow_state(struct kvm_vcpu *vcpu)
{
	if (unlikely(is_hyp_ctxt(vcpu))) {
		sync_shadow_special_regs(vcpu);
		sync_shadow_non_trap_el1_state(vcpu);
		sync_shadow_el1_sysregs(vcpu);
	} else
		sync_special_regs(vcpu);

	vgic_v2_restore_shadow_state(vcpu);
}

void kvm_arm_init_cpu_context(kvm_cpu_context_t *cpu_ctxt)
{
	/* This is to set hw_sys_regs of host_cpu_context */
	cpu_ctxt->hw_sys_regs = cpu_ctxt->sys_regs;
}
