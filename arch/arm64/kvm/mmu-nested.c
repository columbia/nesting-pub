/*
 * Copyright (C) 2017 - Columbia University and Linaro Ltd.
 * Author: Jintack Lim <jintack.lim@linaro.org>
 * Author: Christoffer Dall <cdall@cs.columbia.edu>
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

#include <asm/kvm_arm.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_mmu.h>

struct s2_walk_info {
	unsigned int pgshift;
	unsigned int pgsize;
	unsigned int ps;
	unsigned int sl;
	unsigned int t0sz;
};

static unsigned int ps_to_output_size(unsigned int ps)
{
	switch (ps) {
	case 0: return 32;
	case 1: return 36;
	case 2: return 40;
	case 3: return 42;
	case 4: return 44;
	case 5:
	default:
		return 48;
	}
}

static unsigned int pa_max(void)
{
	 /* We always emulate a VM with maximum PA size of KVM_PHYS_SIZE. */
	return KVM_PHYS_SHIFT;
}

static int esr_s2_fault(struct kvm_vcpu *vcpu, int level, u32 fsc)
{
	u32 esr;

	esr = kvm_vcpu_get_hsr(vcpu) & ~ESR_ELx_FSC;
	esr |= fsc;
	esr |= level & 0x3;
	return esr;
}

int kvm_inject_s2_fault(struct kvm_vcpu *vcpu, u64 esr_el2)
{
	vcpu->arch.ctxt.sys_regs[FAR_EL2] = vcpu->arch.fault.far_el2;
	vcpu->arch.ctxt.sys_regs[HPFAR_EL2] = vcpu->arch.fault.hpfar_el2;

	return kvm_inject_nested_sync(vcpu, esr_el2);
}

static int check_base_s2_limits(struct kvm_vcpu *vcpu, struct s2_walk_info *wi,
				int level, int input_size, int stride)
{
	int start_size;

	/* Check translation limits */
	switch (wi->pgsize) {
	case SZ_64K:
		if (level == 0 || (level == 1 && pa_max() <= 42))
			return -EFAULT;
		break;
	case SZ_16K:
		if (level == 0 || (level == 1 && pa_max() <= 40))
			return -EFAULT;
		break;
	case SZ_4K:
		if (level < 0 || (level == 0 && pa_max() <= 42))
			return -EFAULT;
		break;
	}

	/* Check input size limits */
	if (input_size > pa_max() &&
	    (!vcpu_mode_is_32bit(vcpu) || input_size > 40))
		return -EFAULT;

	/* Check number of entries in starting level table */
	start_size = input_size - ((3 - level) * stride + wi->pgshift);
	if (start_size < 1 || start_size > stride + 4)
		return -EFAULT;

	return 0;
}

/* Check if output is within boundaries */
static int check_output_size(struct kvm_vcpu *vcpu, struct s2_walk_info *wi,
			     phys_addr_t output)
{
	unsigned int output_size = ps_to_output_size(wi->ps);

	if (output_size > pa_max())
		output_size = pa_max();

	if (output_size != 48 && (output & GENMASK_ULL(47, output_size)))
		return -1;

	return 0;
}

/*
 * This is essentially a C-version of the pseudo code from the ARM ARM
 * AArch64.TranslationTableWalk  function.  I strongly recommend looking at
 * that pseudocode in trying to understand this.
 *
 * Must be called with the kvm->srcy read lock held
 */
static int walk_nested_s2_pgd(struct kvm_vcpu *vcpu, phys_addr_t ipa,
			      struct s2_walk_info *wi, struct kvm_s2_trans *out)
{
	u64 vttbr = vcpu->arch.ctxt.sys_regs[VTTBR_EL2];
	int first_block_level, level, stride, input_size, base_lower_bound;
	phys_addr_t base_addr;
	unsigned int addr_top, addr_bottom;
	u64 desc;  /* page table entry */
	int ret;
	phys_addr_t paddr;

	switch (wi->pgsize) {
	case SZ_64K:
	case SZ_16K:
		level = 3 - wi->sl;
		first_block_level = 2;
		break;
	case SZ_4K:
		level = 2 - wi->sl;
		first_block_level = 1;
		break;
	default:
		/* GCC is braindead */
		WARN(1, "Page size is none of 4K, 16K or 64K");
	}

	stride = wi->pgshift - 3;
	input_size = 64 - wi->t0sz;
	if (input_size > 48 || input_size < 25)
		return -EFAULT;

	ret = check_base_s2_limits(vcpu, wi, level, input_size, stride);
	if (WARN_ON(ret))
		return ret;

	if (check_output_size(vcpu, wi, vttbr)) {
		out->esr = esr_s2_fault(vcpu, level, ESR_ELx_FSC_ADDRSZ);
		return 1;
	}

	base_lower_bound = 3 + input_size - ((3 - level) * stride +
			   wi->pgshift);
	base_addr = vttbr & GENMASK_ULL(47, base_lower_bound);

	addr_top = input_size - 1;

	while (1) {
		phys_addr_t index;

		addr_bottom = (3 - level) * stride + wi->pgshift;
		index = (ipa & GENMASK_ULL(addr_top, addr_bottom))
			>> (addr_bottom - 3);

		paddr = base_addr | index;
		ret = kvm_read_guest(vcpu->kvm, paddr, &desc, sizeof(desc));
		if (ret < 0)
			return ret;

		/*
		 * Handle reversedescriptors if endianness differs between the
		 * host and the guest hypervisor.
		 */
		if (vcpu_sys_reg(vcpu, SCTLR_EL2) & SCTLR_EE)
			desc = be64_to_cpu(desc);
		else
			desc = le64_to_cpu(desc);

		/* Check for valid descriptor at this point */
		if (!(desc & 1) || ((desc & 3) == 1 && level == 3)) {
			out->esr = esr_s2_fault(vcpu, level, ESR_ELx_FSC_FAULT);
			return 1;
		}

		/* We're at the final level or block translation level */
		if ((desc & 3) == 1 || level == 3)
			break;

		if (check_output_size(vcpu, wi, desc)) {
			out->esr = esr_s2_fault(vcpu, level, ESR_ELx_FSC_ADDRSZ);
			return 1;
		}

		base_addr = desc & GENMASK_ULL(47, wi->pgshift);

		level += 1;
		addr_top = addr_bottom - 1;
	}

	if (level < first_block_level) {
		out->esr = esr_s2_fault(vcpu, level, ESR_ELx_FSC_FAULT);
		return 1;
	}

	/*
	 * We don't use the contiguous bit in the stage-2 ptes, so skip check
	 * for misprogramming of the contiguous bit.
	 */

	if (check_output_size(vcpu, wi, desc)) {
		out->esr = esr_s2_fault(vcpu, level, ESR_ELx_FSC_ADDRSZ);
		return 1;
	}

	if (!(desc & BIT(10))) {
		out->esr = esr_s2_fault(vcpu, level, ESR_ELx_FSC_ACCESS);
		return 1;
	}

	/* Calculate and return the result */
	paddr = (desc & GENMASK_ULL(47, addr_bottom)) |
		(ipa & GENMASK_ULL(addr_bottom - 1, 0));
	out->output = paddr;
	out->block_size = 1UL << ((3 - level) * stride + wi->pgshift);
	out->readable = desc & (0b01 << 6);
	out->writable = desc & (0b10 << 6);
	out->level = level;
	out->upper_attr = desc & GENMASK_ULL(63, 52);
	return 0;
}

int kvm_walk_nested_s2(struct kvm_vcpu *vcpu, phys_addr_t gipa,
		       struct kvm_s2_trans *result)
{
	u64 vtcr = vcpu->arch.ctxt.sys_regs[VTCR_EL2];
	struct s2_walk_info wi;

	if (!nested_virt_in_use(vcpu))
		return 0;

	wi.t0sz = vtcr & TCR_EL2_T0SZ_MASK;

	switch (vtcr & VTCR_EL2_TG0_MASK) {
	case VTCR_EL2_TG0_4K:
		wi.pgshift = 12;	 break;
	case VTCR_EL2_TG0_16K:
		wi.pgshift = 14;	 break;
	case VTCR_EL2_TG0_64K:
	default:
		wi.pgshift = 16;	 break;
	}
	wi.pgsize = 1UL << wi.pgshift;
	wi.ps = (vtcr & VTCR_EL2_PS_MASK) >> VTCR_EL2_PS_SHIFT;
	wi.sl = (vtcr & VTCR_EL2_SL0_MASK) >> VTCR_EL2_SL0_SHIFT;

	return walk_nested_s2_pgd(vcpu, gipa, &wi, result);
}

/*
 * Returns non-zero if permission fault is handled by injecting it to the next
 * level hypervisor.
 */
int kvm_s2_handle_perm_fault(struct kvm_vcpu *vcpu, phys_addr_t fault_ipa,
			     struct kvm_s2_trans *trans)
{
	unsigned long fault_status = kvm_vcpu_trap_get_fault_type(vcpu);
	bool write_fault = kvm_is_write_fault(vcpu);

	if (fault_status != FSC_PERM)
		return 0;

	if ((write_fault && !trans->writable) ||
	    (!write_fault && !trans->readable)) {
		trans->esr = esr_s2_fault(vcpu, trans->level, ESR_ELx_FSC_PERM);
		return 1;
	}

	return 0;
}

/* expects kvm->mmu_lock to be held */
void kvm_nested_s2_wp(struct kvm *kvm)
{
	struct kvm_nested_s2_mmu *nested_mmu;
	struct list_head *nested_mmu_list = &kvm->arch.nested_mmu_list;

	list_for_each_entry_rcu(nested_mmu, nested_mmu_list, list)
		kvm_stage2_wp_range(kvm, &nested_mmu->mmu, 0, KVM_PHYS_SIZE);
}

/* expects kvm->mmu_lock to be held */
void kvm_nested_s2_clear(struct kvm *kvm)
{
	struct kvm_nested_s2_mmu *nested_mmu;
	struct list_head *nested_mmu_list = &kvm->arch.nested_mmu_list;

	list_for_each_entry_rcu(nested_mmu, nested_mmu_list, list)
		kvm_unmap_stage2_range(kvm, &nested_mmu->mmu, 0, KVM_PHYS_SIZE);
}

/* expects kvm->mmu_lock to be held */
void kvm_nested_s2_flush(struct kvm *kvm)
{
	struct kvm_nested_s2_mmu *nested_mmu;
	struct list_head *nested_mmu_list = &kvm->arch.nested_mmu_list;

	list_for_each_entry_rcu(nested_mmu, nested_mmu_list, list)
		kvm_stage2_flush_range(&nested_mmu->mmu, 0, KVM_PHYS_SIZE);
}

void kvm_nested_s2_free(struct kvm *kvm)
{
	struct kvm_nested_s2_mmu *nested_mmu;
	struct list_head *nested_mmu_list = &kvm->arch.nested_mmu_list;

	list_for_each_entry_rcu(nested_mmu, nested_mmu_list, list)
		__kvm_free_stage2_pgd(kvm, &nested_mmu->mmu);
}

struct kvm_nested_s2_mmu *lookup_nested_mmu(struct kvm_vcpu *vcpu, u64 vttbr)
{
	struct kvm_nested_s2_mmu *mmu;
	u64 virtual_vmid;
	u64 target_vmid = get_vmid(vttbr);
	struct list_head *nested_mmu_list = &vcpu->kvm->arch.nested_mmu_list;

	/* Search a mmu in the list using the virtual VMID as a key */
	list_for_each_entry_rcu(mmu, nested_mmu_list, list) {
		virtual_vmid = get_vmid(mmu->virtual_vttbr);
		if (target_vmid == virtual_vmid)
			return mmu;
	}
	return NULL;
}

/*
 * Clear mappings in the shadow stage 2 page tables for the current VMID from
 * the perspective of the guest hypervisor.
 * This function expects kvm->mmu_lock to be held.
 */
bool kvm_nested_s2_clear_curr_vmid(struct kvm_vcpu *vcpu, phys_addr_t start,
				   u64 size)
{
	struct kvm_nested_s2_mmu *nested_mmu;
	u64 vttbr = vcpu_sys_reg(vcpu, VTTBR_EL2);

	/*
	 * Look up a mmu that is used for the current VMID from the guest
	 * hypervisor's view.
	 */
	nested_mmu = lookup_nested_mmu(vcpu, vttbr);
	if (!nested_mmu)
		return false;

	kvm_unmap_stage2_range(vcpu->kvm, &nested_mmu->mmu, start, size);
	return true;
}

/**
 * create_nested_mmu - create mmu for the given virtual VMID
 *
 * Called from setup_s2_mmu before entering the nested VM to ensure the shadow
 * stage 2 page table is allocated and it is valid to use.
 */
static struct kvm_nested_s2_mmu *create_nested_mmu(struct kvm_vcpu *vcpu,
						   u64 vttbr)
{
	struct kvm_nested_s2_mmu *nested_mmu, *tmp_mmu;
	struct list_head *nested_mmu_list = &vcpu->kvm->arch.nested_mmu_list;
	bool need_free = false;
	int ret;

	nested_mmu = kzalloc(sizeof(struct kvm_nested_s2_mmu), GFP_KERNEL);
	if (!nested_mmu)
		return NULL;

	ret = __kvm_alloc_stage2_pgd(&nested_mmu->mmu);
	if (ret) {
		kfree(nested_mmu);
		return NULL;
	}

	spin_lock(&vcpu->kvm->mmu_lock);
	tmp_mmu = lookup_nested_mmu(vcpu, vttbr);
	if (!tmp_mmu) {
		list_add_rcu(&nested_mmu->list, nested_mmu_list);
	} else {
		/*
		 * Somebody already put a new nested_mmu for this virtual VMID
		 * to the list behind our back.
		 */
		need_free = true;
	}
	spin_unlock(&vcpu->kvm->mmu_lock);

	if (need_free) {
		__kvm_free_stage2_pgd(vcpu->kvm, &nested_mmu->mmu);
		kfree(nested_mmu);
		nested_mmu = tmp_mmu;
	}

	/* The virtual VMID will be used as a key when searching a mmu */
	nested_mmu->virtual_vttbr = vttbr;

	return nested_mmu;
}

static struct kvm_s2_mmu *get_s2_mmu_nested(struct kvm_vcpu *vcpu)
{
	u64 vttbr = vcpu_sys_reg(vcpu, VTTBR_EL2);
	struct kvm_nested_s2_mmu *nested_mmu;

	nested_mmu = lookup_nested_mmu(vcpu, vttbr);
	if (!nested_mmu)
		nested_mmu = create_nested_mmu(vcpu, vttbr);

	return &nested_mmu->mmu;
}

struct kvm_s2_mmu *vcpu_get_active_s2_mmu(struct kvm_vcpu *vcpu)
{
	if (is_hyp_ctxt(vcpu) || !vcpu_nested_stage2_enabled(vcpu))
		return &vcpu->kvm->arch.mmu;

	return get_s2_mmu_nested(vcpu);
}

/*
 * vcpu interface address. This address is supposed to come from the guest's
 * device tree via QEMU. Here we just hardcoded it, but should be fixed.
 */
#define NESTED_VCPU_IF_ADDR	0x08010000
int kvm_nested_mmio_ondemand(struct kvm_vcpu *vcpu, phys_addr_t fault_ipa,
			     phys_addr_t ipa)
{
	int ret = 0;
	phys_addr_t vcpu_base = vgic_vcpu_base();

	if (!nested_virt_in_use(vcpu))
		return 0;

	/* Return if this fault is not from a nested VM */
	if (vcpu->arch.hw_mmu == &vcpu->kvm->arch.mmu)
		return ret;

	if (ipa == NESTED_VCPU_IF_ADDR)  {
		ret = __kvm_phys_addr_ioremap(vcpu->kvm, vcpu->arch.hw_mmu,
					      fault_ipa, vcpu_base,
					      KVM_VGIC_V2_CPU_SIZE, true);
		if (!ret)
			ret = 1;
	}

	return ret;
}
