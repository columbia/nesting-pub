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

static struct kvm_nested_s2_mmu *lookup_nested_mmu(struct kvm_vcpu *vcpu,
						   u64 vttbr)
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
