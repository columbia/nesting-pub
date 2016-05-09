/*
 * Copyright (C) 2016 - Columbia University
 * Author: Jintack Lim <jintack@cs.columbia.edu>
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
#include <asm/kvm_nested.h>

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
	u64 parange = read_sysreg(id_aa64mmfr0_el1) & 7;

	return ps_to_output_size(parange);
}

static int vcpu_inject_s2_perm_fault(struct kvm_vcpu *vcpu, gpa_t ipa,
				     int level)
{
	u32 esr;

	vcpu->arch.ctxt.el2_regs[FAR_EL2] = vcpu->arch.fault.far_el2;
	vcpu->arch.ctxt.el2_regs[HPFAR_EL2] = vcpu->arch.fault.hpfar_el2;
	esr = kvm_vcpu_get_hsr(vcpu) & ~ESR_ELx_FSC;
	esr |= ESR_ELx_FSC_PERM;
	esr |= level & 0x3;
	return kvm_inject_nested_sync(vcpu, esr);
}

static int vcpu_inject_s2_trans_fault(struct kvm_vcpu *vcpu, gpa_t ipa,
				      int level)
{
	u32 esr;

	vcpu->arch.ctxt.el2_regs[FAR_EL2] = vcpu->arch.fault.far_el2;
	vcpu->arch.ctxt.el2_regs[HPFAR_EL2] = vcpu->arch.fault.hpfar_el2;
	esr = kvm_vcpu_get_hsr(vcpu) & ~ESR_ELx_FSC;
	esr |= ESR_ELx_FSC_FAULT;
	esr |= level & 0x3;
	return kvm_inject_nested_sync(vcpu, esr);
}

static int vcpu_inject_s2_addr_sz_fault(struct kvm_vcpu *vcpu, gpa_t ipa,
					int level)
{
	u32 esr;

	vcpu->arch.ctxt.el2_regs[FAR_EL2] = vcpu->arch.fault.far_el2;
	vcpu->arch.ctxt.el2_regs[HPFAR_EL2] = vcpu->arch.fault.hpfar_el2;
	esr = kvm_vcpu_get_hsr(vcpu) & ~ESR_ELx_FSC;
	esr |= ESR_ELx_FSC_ADDRSZ;
	esr |= level & 0x3;
	return kvm_inject_nested_sync(vcpu, esr);
}

static int vcpu_inject_s2_access_flag_fault(struct kvm_vcpu *vcpu, gpa_t ipa,
					    int level)
{
	u32 esr;

	vcpu->arch.ctxt.el2_regs[FAR_EL2] = vcpu->arch.fault.far_el2;
	vcpu->arch.ctxt.el2_regs[HPFAR_EL2] = vcpu->arch.fault.hpfar_el2;
	esr = kvm_vcpu_get_hsr(vcpu) & ~ESR_ELx_FSC;
	esr |= ESR_ELx_FSC_ACCESS;
	esr |= level & 0x3;
	return kvm_inject_nested_sync(vcpu, esr);
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
	u64 vttbr = vcpu->arch.ctxt.el2_regs[VTTBR_EL2];
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

	if (check_output_size(vcpu, wi, vttbr))
		return vcpu_inject_s2_addr_sz_fault(vcpu, ipa, level);

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

		/* Check for valid descriptor at this point */
		if (!(desc & 1) || ((desc & 3) == 1 && level == 3))
			return vcpu_inject_s2_trans_fault(vcpu, ipa, level);

		/* We're at the final level or block translation level */
		if ((desc & 3) == 1 || level == 3)
			break;

		if (check_output_size(vcpu, wi, desc))
			return vcpu_inject_s2_addr_sz_fault(vcpu, ipa, level);

		base_addr = desc & GENMASK_ULL(47, wi->pgshift);

		level += 1;
		addr_top = addr_bottom - 1;
	}

	if (level < first_block_level)
		return vcpu_inject_s2_trans_fault(vcpu, ipa, level);

	/* TODO: Consider checking contiguous bit setting */

	if (check_output_size(vcpu, wi, desc))
		return vcpu_inject_s2_addr_sz_fault(vcpu, ipa, level);

	if (!(desc & BIT(10)))
		return vcpu_inject_s2_access_flag_fault(vcpu, ipa, level);

	/* Calculate and return the result */
	paddr = (desc & GENMASK_ULL(47, addr_bottom)) |
		(ipa & GENMASK_ULL(addr_bottom - 1, 0));
	out->output = paddr;
	out->block_size = 1UL << ((3 - level) * stride + wi->pgshift);
	out->readable = desc & (0b01 << 6);
	out->writable = desc & (0b10 << 6);
	out->level = level;
	return 0;
}

int kvm_walk_nested_s2(struct kvm_vcpu *vcpu, phys_addr_t gipa,
		       struct kvm_s2_trans *result)
{
	u64 vtcr = vcpu->arch.ctxt.el2_regs[VTCR_EL2];
	struct s2_walk_info wi;

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

	/* TODO: Reversedescriptor if SCTLR_EL2.EE == 1 */

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
	    (!write_fault && !trans->readable))
		return vcpu_inject_s2_perm_fault(vcpu, fault_ipa, trans->level);

	return 0;
}

/* expects kvm->mmu_lock to be held */
void kvm_nested_s2_all_vcpus_wp(struct kvm *kvm)
{
	int i;
	struct kvm_vcpu *vcpu;
	struct kvm_nested_s2_mmu *nested_mmu;
	struct list_head *nested_mmu_list;

	kvm_for_each_vcpu(i, vcpu, kvm) {
		if (need_resched() || spin_needbreak(&kvm->mmu_lock))
			cond_resched_lock(&kvm->mmu_lock);

		nested_mmu_list = &vcpu->kvm->arch.nested_mmu_list;
		list_for_each_entry_rcu(nested_mmu, nested_mmu_list, list)
			kvm_stage2_wp_range(kvm, &nested_mmu->mmu,
				    0, KVM_PHYS_SIZE);
	}
}

/* expects kvm->mmu_lock to be held */
void kvm_nested_s2_all_vcpus_unmap(struct kvm *kvm)
{
	int i;
	struct kvm_vcpu *vcpu;
	struct kvm_nested_s2_mmu *nested_mmu;
	struct list_head *nested_mmu_list;

	kvm_for_each_vcpu(i, vcpu, kvm) {
		if (need_resched() || spin_needbreak(&kvm->mmu_lock))
			cond_resched_lock(&kvm->mmu_lock);

		nested_mmu_list = &vcpu->kvm->arch.nested_mmu_list;
		list_for_each_entry_rcu(nested_mmu, nested_mmu_list, list)
			kvm_unmap_stage2_range(&nested_mmu->mmu,
				       0, KVM_PHYS_SIZE);
	}
}

void kvm_nested_s2_all_vcpus_flush(struct kvm *kvm)
{
	int i;
	struct kvm_vcpu *vcpu;
	struct kvm_nested_s2_mmu *nested_mmu;
	struct list_head *nested_mmu_list;

	kvm_for_each_vcpu(i, vcpu, kvm) {
		if (need_resched() || spin_needbreak(&kvm->mmu_lock))
			cond_resched_lock(&kvm->mmu_lock);

		nested_mmu_list = &vcpu->kvm->arch.nested_mmu_list;
		list_for_each_entry_rcu(nested_mmu, nested_mmu_list, list)
			kvm_stage2_flush_range(&nested_mmu->mmu,
				       0, KVM_PHYS_SIZE);
	}
}

void kvm_nested_s2_unmap(struct kvm_vcpu *vcpu)
{
	struct kvm_nested_s2_mmu *nested_mmu;
	struct list_head *nested_mmu_list = &vcpu->kvm->arch.nested_mmu_list;

	list_for_each_entry_rcu(nested_mmu, nested_mmu_list, list)
		kvm_unmap_stage2_range(&nested_mmu->mmu, 0, KVM_PHYS_SIZE);
}

int kvm_nested_s2_init(struct kvm_vcpu *vcpu)
{
	return 0;
}

void kvm_nested_s2_teardown(struct kvm_vcpu *vcpu)
{
	struct kvm_nested_s2_mmu *nested_mmu;
	struct list_head *nested_mmu_list = &vcpu->kvm->arch.nested_mmu_list;

	list_for_each_entry_rcu(nested_mmu, nested_mmu_list, list)
		__kvm_free_stage2_pgd(&nested_mmu->mmu);
}

struct kvm_nested_s2_mmu *get_nested_mmu(struct kvm_vcpu *vcpu, u64 vttbr)
{
	struct kvm_nested_s2_mmu *mmu;
	u64 target_vmid = get_vmid(vttbr);
	struct list_head *nested_mmu_list = &vcpu->kvm->arch.nested_mmu_list;

	list_for_each_entry_rcu(mmu, nested_mmu_list, list) {
		u64 vmid = get_vmid(mmu->virtual_vttbr);

		if (target_vmid == vmid)
			return mmu;
	}
	return NULL;
}

struct kvm_s2_mmu *vcpu_get_active_s2_mmu(struct kvm_vcpu *vcpu)
{
	struct kvm_nested_s2_mmu *nested_mmu;

	/* If we are NOT entering the nested VM, return mmu in kvm_arch */
	if (vcpu_mode_el2(vcpu) || !vcpu_nested_stage2_enabled(vcpu))
		return &vcpu->kvm->arch.mmu;

	/* Otherwise, search for nested_mmu in the list */
	nested_mmu = get_nested_mmu(vcpu, vcpu_el2_reg(vcpu, VTTBR_EL2));

	/* When this function is called, nested_mmu should be in the list */
	BUG_ON(!nested_mmu);

	return &nested_mmu->mmu;
}

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

	spin_lock(&vcpu->kvm->arch.mmu_list_lock);
	tmp_mmu = get_nested_mmu(vcpu, vttbr);
	if (!tmp_mmu)
		list_add_rcu(&nested_mmu->list, nested_mmu_list);
	else /* Somebody already created and put a new nested_mmu to the list */
		need_free = true;
	spin_unlock(&vcpu->kvm->arch.mmu_list_lock);

	if (need_free) {
		__kvm_free_stage2_pgd(&nested_mmu->mmu);
		kfree(nested_mmu);
		nested_mmu = tmp_mmu;
	}

	return nested_mmu;
}

bool handle_vttbr_update(struct kvm_vcpu *vcpu, u64 vttbr)
{
	struct kvm_nested_s2_mmu *nested_mmu;

	/* See if we can relax this */
	if (!vttbr)
		return true;

	nested_mmu = (struct kvm_nested_s2_mmu *)get_nested_mmu(vcpu, vttbr);
	if (!nested_mmu) {
		nested_mmu = create_nested_mmu(vcpu, vttbr);
		if (!nested_mmu)
			return false;
	} else {
		/*
		 * unmap the shadow page table if vttbr_el2 is
		 * changed to different value
		 */
		if (vttbr != nested_mmu->virtual_vttbr)
			kvm_nested_s2_unmap(vcpu);
	}

	nested_mmu->virtual_vttbr = vttbr;

	return true;
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
